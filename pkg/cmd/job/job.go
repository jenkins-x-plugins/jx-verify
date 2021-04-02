package job

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/input"
	"github.com/jenkins-x/jx-helpers/v3/pkg/input/inputfactory"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube/jobs"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube/podlogs"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube/pods"
	"github.com/jenkins-x/jx-helpers/v3/pkg/options"
	"github.com/jenkins-x/jx-helpers/v3/pkg/stringhelpers"
	"github.com/jenkins-x/jx-helpers/v3/pkg/termcolor"
	"github.com/jenkins-x/jx-kube-client/v3/pkg/kubeclient"
	logger "github.com/jenkins-x/jx-logging/v3/pkg/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Options contains the command line arguments for this command
type Options struct {
	options.BaseOptions

	Namespace     string
	Name          string
	Selector      string
	FieldSelector string
	ContainerName string
	Duration      time.Duration
	PollPeriod    time.Duration
	NoTail        bool
	LogFail       bool
	VerifyResult  bool
	ErrOut        io.Writer
	Out           io.Writer
	KubeClient    kubernetes.Interface
	Input         input.Interface
	timeEnd       time.Time
	podStatusMap  map[string]string
}

const (
	// PodResultPrefix the result of the pod status
	PodResultPrefix = "POD RESULT: "

	// PodResultOK if the pod completed successfully
	PodResultOK = "OK"

	// PodResultFailed if the pod failed
	PodResultFailed = "FAILED: "
)

var (
	info = termcolor.ColorInfo

	cmdLong = templates.LongDesc(`
		Verifies that the job(s) with the given label succeeds and tails the log as it executes

`)

	cmdExample = templates.Examples(`
		# verify the BDD job succeeds
		jx verify job -l app=jx-bdd

		# verify the BDD job succeeds using name
		jx verify job --name jx-bdd
`)
)

// NewCmdVerifyJob creates the new command
func NewCmdVerifyJob() (*cobra.Command, *Options) {
	options := &Options{}
	command := &cobra.Command{
		Use:     "job",
		Short:   "Verifies that the job(s) with the given label succeeds and tails the log as it executes",
		Aliases: []string{"logs"},
		Long:    cmdLong,
		Example: cmdExample,
		Run: func(command *cobra.Command, args []string) {
			err := options.Run()
			helper.CheckErr(err)
		},
	}
	command.Flags().StringVarP(&options.Namespace, "namespace", "n", "", "the namespace where the jobs run. If not specified it will look in: jx-git-operator and jx")
	command.Flags().StringVarP(&options.Name, "name", "", "", "the name of the job to use")
	command.Flags().StringVarP(&options.Selector, "selector", "l", "", "the selector of the job pods")
	command.Flags().StringVarP(&options.FieldSelector, "field-selector", "f", "", "the field selector to use to query jobs")
	command.Flags().StringVarP(&options.ContainerName, "container", "c", "", "the name of the container in the job to log")
	command.Flags().DurationVarP(&options.Duration, "duration", "d", time.Minute*60, "how long to wait for a Job to be active and a Pod to be ready")
	command.Flags().DurationVarP(&options.PollPeriod, "poll", "", time.Second*1, "duration between polls for an active Job or Pod")
	command.Flags().BoolVarP(&options.LogFail, "log-fail", "", false, "rather than failing the command lets just log that the job failed. e.g. this lets us run tests inside a Terraform Pod without the terraform operator thinking the terraform failed.")
	command.Flags().BoolVarP(&options.VerifyResult, "verify-result", "", false, "if the pod succeeds lets look for the last line starting with "+PodResultPrefix+" to determine the test result")

	options.BaseOptions.AddBaseFlags(command)

	return command, options
}

func (o *Options) Run() error {
	err := o.Validate()
	if err != nil {
		return err
	}

	client := o.KubeClient
	selector := o.Selector
	ns := o.Namespace

	if o.Name != "" {
		selector = "job-name=" + o.Name
		_, err = o.waitForJobToExist(client, ns, o.Name)
		if err != nil {
			return errors.Wrapf(err, "failed to wait for job %s", o.Name)
		}
		err = o.viewActiveJobLog(client, ns, selector, o.Name)
		return o.handleErrorReporting(err)
	}

	jobs, err := GetSortedJobs(client, ns, selector, o.FieldSelector)
	if err != nil {
		return errors.Wrapf(err, "failed to get jobs")
	}

	err = o.pickJobToLog(client, ns, selector, jobs)
	return o.handleErrorReporting(err)
}

func (o *Options) handleErrorReporting(err error) error {
	if !o.LogFail {
		return err
	}

	if err != nil {
		logger.Logger().Infof("%s%s%s", PodResultPrefix, PodResultFailed, err.Error())
	} else {
		logger.Logger().Infof("%s%s", PodResultPrefix, PodResultOK)
	}
	return nil
}

func (o *Options) viewActiveJobLog(client kubernetes.Interface, ns, selector, jobName string) error {
	var foundPods []string
	logger.Logger().Infof("waiting for a running pod in namespace %s with selector %s", info(ns), info(selector))
	for {
		complete, pod, err := o.waitForJobCompleteOrPodRunning(client, ns, selector, jobName)
		if err != nil {
			return err
		}
		if complete {
			if o.VerifyResult {
				return o.verifyResultInLastPod(client, ns, selector)
			}
			return nil
		}
		if pod == nil {
			return errors.Errorf("No pod found for namespace %s with selector %v", ns, selector)
		}

		if time.Now().After(o.timeEnd) {
			return errors.Errorf("timed out after waiting for duration %s", o.Duration.String())
		}

		// lets verify the container name
		containerName := o.ContainerName
		if containerName == "" {
			containerName = pod.Spec.Containers[0].Name
		}
		err = verifyContainerName(pod, containerName)
		if err != nil {
			return err
		}
		podName := pod.Name
		if stringhelpers.StringArrayIndex(foundPods, podName) < 0 {
			foundPods = append(foundPods, podName)
		}
		logger.Logger().Infof("\ntailing pod %s\n\n", info(podName))

		err = podlogs.TailLogs(ns, podName, containerName, o.ErrOut, o.Out)
		if err != nil {
			logger.Logger().Warnf("failed to tail log: %s", err.Error())
		}
		pod, err = client.CoreV1().Pods(ns).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return errors.Wrapf(err, "failed to get pod %s in namespace %s", podName, ns)
		}
		if pods.IsPodCompleted(pod) {
			if pods.IsPodSucceeded(pod) {
				logger.Logger().Infof("pod %s has %s", info(podName), info("Succeeded"))
			} else {
				logger.Logger().Infof("pod %s has %s", info(podName), termcolor.ColorError(string(pod.Status.Phase)))
			}
		} else if pod.DeletionTimestamp != nil {
			logger.Logger().Infof("pod %s is %s", info(podName), termcolor.ColorWarning("Terminating"))
		}
	}
}

// Validate verifies the settings are correct and we can lazy create any required resources
func (o *Options) Validate() error {
	if o.Selector == "" {
		if o.Name == "" {
			return options.MissingOption("selector")
		}
	}
	if o.FieldSelector == "" && o.Name != "" {
		o.FieldSelector = "metadata.name=" + o.Name
	}
	if o.NoTail {
		return nil
	}
	if o.ErrOut == nil {
		o.ErrOut = os.Stderr
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}

	var err error
	o.KubeClient, err = kube.LazyCreateKubeClientWithMandatory(o.KubeClient, true)
	if err != nil {
		return errors.Wrapf(err, "failed to create kubernetes client")
	}
	if o.Namespace == "" {
		o.Namespace, err = kubeclient.CurrentNamespace()
		if err != nil {
			return errors.Wrapf(err, "failed to detect current namespace. Try supply --namespace")
		}
	}
	if o.Input == nil {
		o.Input = inputfactory.NewInput(&o.BaseOptions)
	}
	o.timeEnd = time.Now().Add(o.Duration)
	return nil
}

func (o *Options) waitForJobToExist(client kubernetes.Interface, ns, jobName string) (*batchv1.Job, error) {
	logged := false

	for {
		job, err := client.BatchV1().Jobs(ns).Get(context.TODO(), jobName, metav1.GetOptions{})
		if err == nil && job != nil {
			logger.Logger().Infof("found Job %s in namespace %s", info(jobName), info(ns))
			return job, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, errors.Wrapf(err, "failed to look for job %s in namespace %s", jobName, ns)
		}

		if !logged {
			logged = true
			logger.Logger().Infof("waiting up to %s for the Job %s to be created", o.Duration.String(), info(jobName))
		}
		if time.Now().After(o.timeEnd) {
			return nil, errors.Errorf("timed out after waiting for duration %s", o.Duration.String())
		}
		time.Sleep(o.PollPeriod)
	}
}

func (o *Options) verifyResultInLastPod(client kubernetes.Interface, ns, selector string) error {
	opts := metav1.ListOptions{
		LabelSelector: selector,
	}
	podInterface := client.CoreV1().Pods(ns)
	ctx := context.TODO()
	podList, err := podInterface.List(ctx, opts)
	if err != nil && apierrors.IsNotFound(err) {
		err = nil
	}
	if err != nil {
		return errors.Wrapf(err, "failed to query ready pod in namespace %s with selector %s", ns, selector)
	}
	if podList == nil || len(podList.Items) == 0 {
		return errors.Errorf("no pods found in namespace %s with selector %s", ns, selector)
	}
	pods := podList.Items

	// lets find the latest pod
	pod := pods[0]
	for i := 1; i < len(pods); i++ {
		p := pods[i]
		if p.CreationTimestamp.After(pod.CreationTimestamp.Time) {
			pod = p
		}
	}

	// lets get the log of the pod
	result := podInterface.GetLogs(pod.Name, &v1.PodLogOptions{
		Container: o.ContainerName,
	}).Do(ctx)
	data, err := result.Raw()
	if err != nil {
		return errors.Wrapf(err, "failed to read logs in namespace %s pod %s", ns, pod.Name)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, PodResultPrefix) {
			continue
		}
		remaining := strings.TrimPrefix(line, PodResultPrefix)
		remaining = strings.TrimSpace(remaining)
		logger.Logger().Infof("pod %s has result %s", info(pod.Name), info(remaining))
		if remaining == PodResultOK {
			return nil
		}
		return errors.Errorf("pod %s %s", pod.Name, remaining)
	}
	return errors.Errorf("pod %s did not output expected line: %s", pod.Name, PodResultPrefix)
}

func (o *Options) waitForJobCompleteOrPodRunning(client kubernetes.Interface, ns, selector, jobName string) (bool, *corev1.Pod, error) {
	if o.podStatusMap == nil {
		o.podStatusMap = map[string]string{}
	}

	for {
		complete, job, err := o.checkIfJobComplete(client, ns, jobName)
		if err != nil {
			return false, nil, errors.Wrapf(err, "failed to check for Job %s complete", jobName)
		}
		if complete {
			if job != nil && !jobs.IsJobSucceeded(job) {
				return true, nil, errors.Errorf("job %s failed", jobName)
			}
			return true, nil, nil
		}

		pod, err := pods.GetRunningPodForSelector(client, ns, selector)
		if err != nil {
			return false, pod, errors.Wrapf(err, "failed to query ready pod in namespace %s with selector %s", ns, selector)
		}
		if pod != nil {
			status := pods.PodStatus(pod)
			if o.podStatusMap[pod.Name] != status && !pods.IsPodCompleted(pod) && pod.DeletionTimestamp == nil {
				logger.Logger().Infof("pod %s has status %s", termcolor.ColorInfo(pod.Name), termcolor.ColorInfo(status))
				o.podStatusMap[pod.Name] = status
			}
			if pod.Status.Phase == v1.PodRunning || pods.IsPodReady(pod) {
				return false, pod, nil
			}
		}

		if time.Now().After(o.timeEnd) {
			return false, nil, errors.Errorf("timed out after waiting for duration %s", o.Duration.String())
		}
		time.Sleep(o.PollPeriod)
	}
}

func (o *Options) checkIfJobComplete(client kubernetes.Interface, ns, name string) (bool, *batchv1.Job, error) {
	job, err := client.BatchV1().Jobs(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if job == nil || err != nil {
		return false, nil, errors.Wrapf(err, "failed to list jobList in namespace %s name %s", ns, name)
	}
	if jobs.IsJobFinished(job) {
		if jobs.IsJobSucceeded(job) {
			logger.Logger().Infof("job %s has %s", info(job.Name), info("Succeeded"))
			return true, job, nil
		}
		logger.Logger().Infof("job %s has %s", info(job.Name), termcolor.ColorError("Failed"))
		return true, job, nil
	}
	logger.Logger().Debugf("job %s is not completed yet", info(job.Name))
	return false, job, nil
}

func (o *Options) pickJobToLog(client kubernetes.Interface, ns, selector string, jobs []batchv1.Job) error {
	var names []string
	m := map[string]*batchv1.Job{}
	for i := range jobs {
		j := &jobs[i]
		name := toJobName(j, len(jobs)-i)
		m[name] = j
		names = append(names, name)
	}

	name, err := o.Input.PickNameWithDefault(names, "select the Job to view:", "", "select which job you wish to log")
	if err != nil {
		return errors.Wrapf(err, "failed to pick a job name")
	}
	if name == "" {
		return errors.Errorf("no jobs to view. Try add --active to wait for the next job")
	}
	return o.viewActiveJobLog(client, ns, selector, name)
}

func toJobName(j *batchv1.Job, number int) string {
	status := jobStatus(j)
	d := time.Since(j.CreationTimestamp.Time).Round(time.Minute)
	return fmt.Sprintf("#%d started %s %s", number, d.String(), status)
}

func jobStatus(j *batchv1.Job) string {
	if jobs.IsJobSucceeded(j) {
		return "Succeeded"
	}
	if jobs.IsJobFinished(j) {
		return "Failed"
	}
	if j.Status.Active > 0 {
		return "Running"
	}
	return "Pending"
}

func verifyContainerName(pod *corev1.Pod, name string) error {
	var names []string
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return nil
		}
		names = append(names, pod.Spec.Containers[i].Name)
	}
	sort.Strings(names)
	return errors.Errorf("invalid container name %s for pod %s. Available names: %s", name, pod.Name, strings.Join(names, ", "))
}

// GetSortedJobs gets the jobs with an optional commit sha filter
func GetSortedJobs(client kubernetes.Interface, ns, selector, fieldSelector string) ([]batchv1.Job, error) {
	jobList, err := client.BatchV1().Jobs(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector,
		FieldSelector: fieldSelector,
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, errors.Wrapf(err, "failed to list jobList in namespace %s selector %s", ns, selector)
	}

	answer := jobList.Items
	sort.Slice(answer, func(i, j int) bool {
		j1 := answer[i]
		j2 := answer[j]
		return j2.CreationTimestamp.Before(&j1.CreationTimestamp)
	})
	return answer, nil
}
