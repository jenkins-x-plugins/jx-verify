package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jenkins-x-plugins/jx-verify/pkg/rootcmd"
	"github.com/jenkins-x/jx-helpers/v3/pkg/builds"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cmdrunner"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube/pods"
	"github.com/jenkins-x/jx-helpers/v3/pkg/options"
	"github.com/jenkins-x/jx-helpers/v3/pkg/table"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	cmdLong = templates.LongDesc(`
		Verifies the installation is ready
`)

	cmdExample = templates.Examples(`
		# populate the ingress domain if not using a configured 'ingress.domain' setting
		jx verify install

			`)
)

type Options struct {
	options.BaseOptions

	KubeClient       kubernetes.Interface
	Namespace        string
	IncludeBuildPods bool
	CustomSelector   string
	WaitDuration     time.Duration
	PollPeriod       time.Duration
	Out              io.Writer
	CommandRunner    cmdrunner.CommandRunner
}

func NewCmdVerifyInstall() (*cobra.Command, *Options) {
	o := &Options{}

	cmd := &cobra.Command{
		Use:     "install",
		Short:   "Verifies the installation is ready",
		Long:    cmdLong,
		Example: fmt.Sprintf(cmdExample, rootcmd.BinaryName),
		Run: func(_ *cobra.Command, _ []string) {
			err := o.Run()
			helper.CheckErr(err)
		},
	}
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "if not specified uses the default namespace")
	cmd.Flags().DurationVarP(&o.WaitDuration, "pod-wait-time", "w", 2*time.Minute, "The default wait time to wait for the pods to be ready")
	cmd.Flags().DurationVarP(&o.PollPeriod, "poll", "p", 10*time.Second, "The period between polls")
	cmd.Flags().BoolVarP(&o.IncludeBuildPods, "include-build", "", false, "Include build pods")
	cmd.Flags().StringVarP(&o.CustomSelector, "selector", "l", "", "Custom selector (label query) for pods")

	o.BaseOptions.AddBaseFlags(cmd)
	return cmd, o
}

// Validate verfies options and values are setup
func (o *Options) Validate() error {
	var err error
	o.KubeClient, o.Namespace, err = kube.LazyCreateKubeClientAndNamespace(o.KubeClient, o.Namespace)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.CommandRunner == nil {
		o.CommandRunner = cmdrunner.DefaultCommandRunner
	}
	return nil
}

// Run runs the command
func (o *Options) Run() error {
	err := o.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate options: %w", err)
	}

	log.Logger().Infof("Checking pod statuses")

	end := time.Now().Add(o.WaitDuration)
	logWaiting := false

	for {
		table, err := o.waitForReadyPods(o.KubeClient, o.Namespace)
		if err == nil {
			table.Render()
			return nil
		}

		if o.WaitDuration.Seconds() == 0 {
			table.Render()
			return err
		}

		if time.Now().After(end) {
			table.Render()
			return fmt.Errorf("timed out after waiting %s for the pods to become ready: %w", o.WaitDuration.String(), err)
		}

		if !logWaiting {
			logWaiting = true
			log.Logger().Infof("waiting up to %s for pods to be ready", o.WaitDuration.String())
		}
		time.Sleep(o.PollPeriod)
	}
}

func (o *Options) waitForReadyPods(kubeClient kubernetes.Interface, ns string) (table.Table, error) {
	tbl := table.CreateTable(o.Out)

	var listOptions metav1.ListOptions
	if o.CustomSelector != "" {
		listOptions = metav1.ListOptions{
			LabelSelector: o.CustomSelector,
		}
	} else if o.IncludeBuildPods {
		listOptions = metav1.ListOptions{}
	} else {
		listOptions = metav1.ListOptions{
			LabelSelector: fmt.Sprintf("!%s", builds.LabelPipelineRunName),
		}
	}

	ctx := context.Background()
	podList, err := kubeClient.CoreV1().Pods(ns).List(ctx, listOptions)
	if err != nil {
		return tbl, fmt.Errorf("failed to list the PODs in namespace '%s': %w", ns, err)
	}

	tbl.AddRow("POD", "STATUS")

	var f *os.File

	if o.Verbose {
		log.Logger().Infof("Creating verify-pod.log file")
		f, err = os.Create("verify-pod.log")
		if err != nil {
			return tbl, fmt.Errorf("error creating log file: %w", err)
		}
		defer f.Close()
	}

	notReadyPods := []string{}

	notReadyPhases := map[string][]string{}

	for k := range podList.Items {
		pod := podList.Items[k]
		podName := pod.ObjectMeta.Name
		phase := pod.Status.Phase

		if phase == corev1.PodFailed && o.Verbose {
			c := &cmdrunner.Command{
				Name: "kubectl",
				Args: []string{"logs", podName},
			}
			text, err := o.CommandRunner(c)
			if err != nil {
				return tbl, fmt.Errorf("failed to get the Kube pod logs: %w", err)
			}
			if f != nil {
				_, err = fmt.Fprintf(f, "Logs for pod %s:\n", podName)
				if err != nil {
					return tbl, fmt.Errorf("error writing log file: %w", err)
				}
				_, err = f.WriteString(text)
				if err != nil {
					return tbl, fmt.Errorf("error writing log file: %w", err)
				}
			}
		}
		tbl.AddRow(podName, string(phase))

		if !pods.IsPodCompleted(&pod) && !pods.IsPodReady(&pod) {
			notReadyPods = append(notReadyPods, pod.Name)
			key := string(phase)
			notReadyPhases[key] = append(notReadyPhases[key], pod.Name)
		}
	}
	if len(notReadyPods) > 0 {
		phaseSlice := []string{}
		for k, list := range notReadyPhases {
			phaseSlice = append(phaseSlice, fmt.Sprintf("%s: %s", k, strings.Join(list, ", ")))
		}
		return tbl, fmt.Errorf("the following podList are not ready:\n%s", strings.Join(phaseSlice, "\n"))
	}
	return tbl, nil
}
