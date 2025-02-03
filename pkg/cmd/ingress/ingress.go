package ingress

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"os"
	"time"

	jxcore "github.com/jenkins-x/jx-api/v4/pkg/apis/core/v4beta1"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-helpers/v3/pkg/termcolor"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// DefaultIngressNamespace default namespace fro ingress controller
	DefaultIngressNamespace = "nginx"
	// DefaultIngressServiceName default name for ingress controller service and deployment
	DefaultIngressServiceName = "ingress-nginx-controller"
)

var (
	cmdLong = templates.LongDesc(`
		Verifies the ingress configuration defaulting the ingress domain if necessary
`)

	cmdExample = templates.Examples(`
		# populate the ingress domain if not using a configured 'ingress.domain' setting
		jx verify ingress

			`)
)

type Options struct {
	KubeClient       kubernetes.Interface
	Dir              string
	IngressNamespace string
	IngressService   string
}

func NewCmdVerifyIngress() (*cobra.Command, *Options) {
	o := &Options{}

	cmd := &cobra.Command{
		Use:     "ingress",
		Short:   "Verifies the ingress configuration defaulting the ingress domain if necessary",
		Long:    cmdLong,
		Example: cmdExample,
		Run: func(_ *cobra.Command, _ []string) {
			err := o.Run()
			helper.CheckErr(err)
		},
	}
	cmd.Flags().StringVarP(&o.Dir, "dir", "d", ".", "the directory to look for the values.yaml file")
	cmd.Flags().StringVarP(&o.IngressNamespace, "ingress-namespace", "", "", "The namespace for the Ingress controller. If not specified it defaults to $JX_INGRESS_NAMESPACE. Otherwise it defaults to: "+DefaultIngressNamespace)
	cmd.Flags().StringVarP(&o.IngressService, "ingress-service", "", "", "The name of the Ingress controller Service. If not specified it defaults to $JX_INGRESS_SERVICE. Otherwise it defaults to: "+DefaultIngressServiceName)
	return cmd, o
}

func (o *Options) Run() error {
	if o.IngressNamespace == "" {
		o.IngressNamespace = os.Getenv("JX_INGRESS_NAMESPACE")
		if o.IngressNamespace == "" {
			o.IngressNamespace = DefaultIngressNamespace
		}
	}
	if o.IngressService == "" {
		o.IngressService = os.Getenv("JX_INGRESS_SERVICE")
		if o.IngressService == "" {
			o.IngressService = DefaultIngressServiceName
		}
	}

	var err error
	if o.Dir == "" {
		o.Dir, err = os.Getwd()
		if err != nil {
			return err
		}
	}

	o.KubeClient, err = kube.LazyCreateKubeClient(o.KubeClient)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	requirementsResource, requirementsFileName, err := jxcore.LoadRequirementsConfig(o.Dir, false)
	if err != nil {
		return fmt.Errorf("failed to load Jenkins X requirements: %w", err)
	}
	requirements := &requirementsResource.Spec

	err = o.discoverIngressDomain(requirements, requirementsFileName)
	if err != nil {
		return err
	}

	// TLS uses cert-manager to ask LetsEncrypt for a signed certificate
	if requirements.Ingress.TLS.Enabled {
		if requirements.Ingress.IsAutoDNSDomain() {
			return fmt.Errorf("TLS is not supported with automated domains like %s, you will need to use a real domain you own", requirements.Ingress.Domain)
		}
		_, err = mail.ParseAddress(requirements.Ingress.TLS.Email)
		if err != nil {
			return fmt.Errorf("You must provide a valid email address to enable TLS so you can receive notifications from LetsEncrypt about your certificates: %w", err)
		}
	}

	err = verifyDockerRegistry(o.KubeClient, requirements)
	if err != nil {
		log.Logger().Errorf("failed %s", err.Error())
	}
	helper.CheckErr(err)

	return requirementsResource.SaveConfig(requirementsFileName)
}

func (o *Options) discoverIngressDomain(requirements *jxcore.RequirementsConfig, requirementsFileName string) error {
	if requirements.Ingress.IgnoreLoadBalancer {
		log.Logger().Infof("ignoring the load balancer to detect a public ingress domain")
		return nil
	}
	client := o.KubeClient
	var domain string

	// TODO - Do we want stronger assertions than we just specified the domain in requirements file?
	if requirements.Ingress.Domain != "" && requirements.Ingress.Domain != "change.me" {
		return nil
	}
	domain, err := getDomain(client, "",
		o.IngressNamespace,
		o.IngressService)
	if err != nil {
		return fmt.Errorf("getting a domain for ingress service %s/%s: %w", o.IngressNamespace, o.IngressService, err)
	}
	if domain == "" {
		// TODO - Shouldn't we always check/wait for ingress controller to verify domain - feels like safer/stronger verification
		hasHost, err := waitForIngressControllerHost(client, o.IngressNamespace, o.IngressService)
		if err != nil {
			return fmt.Errorf("getting a domain for ingress service %s/%s: %w", o.IngressNamespace, o.IngressService, err)
		}
		if hasHost {
			domain, err = getDomain(client, "",
				o.IngressNamespace,
				o.IngressService)
			if err != nil {
				return fmt.Errorf("getting a domain for ingress service %s/%s: %w", o.IngressNamespace, o.IngressService, err)
			}
		} else {
			log.Logger().Warnf("could not find host for  ingress service %s/%s\n", o.IngressNamespace, o.IngressService)
		}
	}

	if domain == "" {
		return fmt.Errorf("failed to discover domain for ingress service %s/%s", o.IngressNamespace, o.IngressService)
	}
	requirements.Ingress.Domain = domain

	log.Logger().Infof("defaulting the domain to %s and modified %s\n", termcolor.ColorInfo(domain), termcolor.ColorInfo(requirementsFileName))
	return nil
}

func waitForIngressControllerHost(kubeClient kubernetes.Interface, ns, serviceName string) (bool, error) {
	loggedWait := false
	serviceInterface := kubeClient.CoreV1().Services(ns)

	if serviceName == "" || ns == "" {
		return false, nil
	}
	_, err := serviceInterface.Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	fn := func() (bool, error) {
		svc, err := serviceInterface.Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// lets get the ingress service status
		for _, lb := range svc.Status.LoadBalancer.Ingress {
			if lb.Hostname != "" || lb.IP != "" {
				return true, nil
			}
		}

		if !loggedWait {
			loggedWait = true
			log.Logger().Infof("waiting for external Host on the ingress service %s in namespace %s ...", serviceName, ns)
		}
		return false, nil
	}
	err = retryUntilTrueOrTimeout(time.Minute*5, time.Second*3, fn)
	if err != nil {
		return false, err
	}
	return true, nil
}

// retryUntilTrueOrTimeout waits until complete is true, an error occurs or the timeout
func retryUntilTrueOrTimeout(timeout, sleep time.Duration, call func() (bool, error)) (err error) {
	timeoutTime := time.Now().Add(timeout)

	for i := 0; ; i++ {
		complete, err := call()
		if complete || err != nil {
			return err
		}
		if time.Now().After(timeoutTime) {
			return fmt.Errorf("timed out after %s, last error: %s", timeout.String(), err)
		}

		time.Sleep(sleep)
	}
}

// getDomain returns the domain name, trying to infer it either from various Kubernetes resources or cloud provider.
func getDomain(client kubernetes.Interface, domain, ingressNamespace, ingressService string) (string, error) {
	address := ""
	log.Logger().Infof("Waiting to find the external host name of the ingress controller Service in namespace %s with name %s",
		termcolor.ColorInfo(ingressNamespace), termcolor.ColorInfo(ingressService))
	svc, err := client.CoreV1().Services(ingressNamespace).Get(context.TODO(), ingressService, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if svc != nil {
		for _, v := range svc.Status.LoadBalancer.Ingress {
			if v.IP != "" {
				address = v.IP
			} else if v.Hostname != "" {
				address = v.Hostname
			}
		}
	}

	defaultDomain := address

	if address != "" {
		aip := net.ParseIP(address)
		if aip == nil {
			log.Logger().Infof("The Ingress address %s is not an IP address. We recommend we try resolve it to a public IP address and use that for the domain to access services externally.",
				termcolor.ColorInfo(address))

			addressIP := ""
			log.Logger().Infof("Waiting for %s to be resolvable to an IP address...", termcolor.ColorInfo(address))
			f := func() error {
				ips, err := net.LookupIP(address)
				if err == nil {
					for _, ip := range ips {
						t := ip.String()
						if t != "" && !ip.IsLoopback() {
							addressIP = t
							return nil
						}
					}
				}
				return fmt.Errorf("address cannot be resolved yet %s", address)
			}
			err := retryQuiet(5*6, time.Second*10, f)
			if err != nil {
				return "", err
			}

			if addressIP == "" {
				log.Logger().Infof("Still not managed to resolve address %s into an IP address. Please try figure out the domain by hand", address)
				// TODO - We should probably return error here rather than silently continue
			} else {
				log.Logger().Infof("%s resolved to IP %s", termcolor.ColorInfo(address), termcolor.ColorInfo(addressIP))
				address = addressIP

				// its an IP address so lets append a DNS resolver so we can use it with DNS sub domains for ingress
				defaultDomain = fmt.Sprintf("%s.nip.io", address)
			}
		} else {
			// its an IP address so lets append a DNS resolver so we can use it with DNS sub domains for ingress
			defaultDomain = fmt.Sprintf("%s.nip.io", address)
		}
	}

	if domain == "" {
		log.Logger().Infof("No domain flag provided so using default %s to generate Ingress rules", defaultDomain)
		return defaultDomain, nil
	} else if domain != defaultDomain {
		log.Logger().Infof("You can now configure your wildcard DNS %s to point to %s", domain, address)
	}

	return domain, nil
}

// retryQuiet executes a given function call with retry when an error occurs without printing any logs
func retryQuiet(attempts int, sleep time.Duration, call func() error) error {
	lastMessage := ""
	dot := false

	var err error
	for i := 0; ; i++ {
		err := call()
		if err == nil {
			if dot {
				log.Logger().Info("")
			}
			return nil
		}

		if i >= (attempts - 1) {
			break
		}

		time.Sleep(sleep)

		message := fmt.Sprintf("retrying after error: %s", err)
		if lastMessage == message {
			log.Logger().Info(".")
			dot = true
		} else {
			lastMessage = message
			if dot {
				dot = false
				log.Logger().Info("")
			}
			log.Logger().Warnf("%s\n", lastMessage)
		}
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

// Validate checks the command is able to execute
func (o *Options) Validate() error {
	var err error
	o.KubeClient, err = kube.LazyCreateKubeClient(o.KubeClient)
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}
	return nil
}

// verifyDockerRegistry
func verifyDockerRegistry(client kubernetes.Interface, requirements *jxcore.RequirementsConfig) error {
	log.Logger().Infof("now verifying docker registry ingress setup")

	if requirements.Cluster.Registry != "" {
		// if the registry is an IP address then lets still default as the service could have been recreated
		addr := net.ParseIP(requirements.Cluster.Registry)
		if addr == nil {
			return nil
		}
	}
	switch requirements.Cluster.Provider {
	case "kubernetes", "kind", "docker", "minikube", "minishift":
		ns := jxcore.DefaultNamespace

		svc, err := client.CoreV1().Services(ns).Get(context.TODO(), "docker-registry", metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to list services in namespace %s so we can default the registry host: %w", ns, err)
		}

		if svc != nil && svc.Spec.ClusterIP != "" {
			requirements.Cluster.Registry = svc.Spec.ClusterIP
		} else {
			log.Logger().Warnf("could not find the clusterIP for the service docker-registry in the namespace %s so that we could default the container registry host", ns)
			return nil
		}

		return nil

	default:
		return nil
	}
}
