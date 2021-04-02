package ingress

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"os"

	jxcore "github.com/jenkins-x/jx-api/v4/pkg/apis/core/v4beta1"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"
	"github.com/pkg/errors"
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
		Run: func(cmd *cobra.Command, args []string) {
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
		return errors.Wrapf(err, "failed to create kubernetes client")
	}

	requirementsResource, requirementsFileName, err := jxcore.LoadRequirementsConfig(o.Dir, false)
	if err != nil {
		return errors.Wrapf(err, "failed to load Jenkins X requirements")
	}
	requirements := &requirementsResource.Spec

	// TLS uses cert-manager to ask LetsEncrypt for a signed certificate
	if requirements.Ingress.TLS.Enabled {
		if requirements.Ingress.IsAutoDNSDomain() {
			return fmt.Errorf("TLS is not supported with automated domains like %s, you will need to use a real domain you own", requirements.Ingress.Domain)
		}
		_, err = mail.ParseAddress(requirements.Ingress.TLS.Email)
		if err != nil {
			return errors.Wrap(err, "You must provide a valid email address to enable TLS so you can receive notifications from LetsEncrypt about your certificates")
		}
	}

	err = verifyDockerRegistry(o.KubeClient, requirements)
	if err != nil {
		log.Logger().Errorf("failed %s", err.Error())
	}
	helper.CheckErr(err)

	return requirementsResource.SaveConfig(requirementsFileName)
}

// Validate checks the command is able to execute
func (o *Options) Validate() error {
	var err error
	o.KubeClient, err = kube.LazyCreateKubeClient(o.KubeClient)
	if err != nil {
		return errors.Wrapf(err, "failed to create kube client")
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
			return errors.Wrapf(err, "failed to list services in namespace %s so we can default the registry host", ns)
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
