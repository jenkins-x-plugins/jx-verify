package pods

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/jenkins-x-plugins/jx-verify/pkg/rootcmd"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube/pods"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
)

// ErrImagePullMessage the message on an event if it can't pull a pod
const ErrImagePullMessage = "Error: ErrImagePull"

// ErrImagePullBackOffMessage if we are backing off
const ErrImagePullBackOffMessage = "Error: ImagePullBackOff"

var (
	cmdLong = templates.LongDesc(`
		Verifies that all pods start OK in the current namespace; killing any Pods which have ErrImagePul
`)

	cmdExample = templates.Examples(`
		# populate the pods don't have missing images
		jx verify pods

			`)
)

type Options struct {
	KubeClient kubernetes.Interface
	Namespace  string
	Selector   string
	PodCount   int
	IsReady    atomic.Value
	readyPods  map[string]bool
	stop       chan struct{}
}

func NewCmdVerifyPods() (*cobra.Command, *Options) {
	o := &Options{}

	cmd := &cobra.Command{
		Use:     "pods",
		Short:   "Verifies that all pods start OK in the current namespace; killing any Pods which have ErrImagePull",
		Long:    cmdLong,
		Aliases: []string{"pod"},
		Example: fmt.Sprintf(cmdExample, rootcmd.BinaryName),
		Run: func(_ *cobra.Command, _ []string) {
			err := o.Run()
			helper.CheckErr(err)
		},
	}
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "The namespace to look for events")
	cmd.Flags().StringVarP(&o.Selector, "selector", "s", "", "The selector to query for all pods being running")
	cmd.Flags().IntVarP(&o.PodCount, "count", "c", 2, "The minimum Ready pod count required matching the selector before terminating")

	return cmd, o
}

func (o *Options) Run() error {
	var err error

	if o.readyPods == nil {
		o.readyPods = map[string]bool{}
	}
	o.KubeClient, o.Namespace, err = kube.LazyCreateKubeClientAndNamespace(o.KubeClient, o.Namespace)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	o.stop = make(chan struct{})
	defer close(o.stop)
	defer runtime.HandleCrash()

	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		o.KubeClient,
		time.Minute*10,
		informers.WithNamespace(o.Namespace),
	)

	eventInformer := informerFactory.Core().V1().Events().Informer()

	_, _ = eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e := obj.(*v1.Event)
			if e == nil {
				log.Logger().Warnf("no Event found for %v", obj)
				return
			}
			o.OnEvent(e, o.Namespace)
			log.Logger().Debugf("added Event %s", e.Name)
		},
		UpdateFunc: func(_, obj interface{}) {
			e := obj.(*v1.Event)
			if e == nil {
				log.Logger().Warnf("no Event found for %v", obj)
				return
			}
			o.OnEvent(e, o.Namespace)
			log.Logger().Debugf("updated Event %s", e.Name)
		},
	})

	podInformer := informerFactory.Core().V1().Pods().Informer()

	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			p := obj.(*v1.Pod)
			o.OnPod(p)
			log.Logger().Debugf("added Pod %s", p.Name)
		},
		UpdateFunc: func(_, new interface{}) {
			p := new.(*v1.Pod)
			o.OnPod(p)
			log.Logger().Debugf("updated Pod %s", p.Name)
		},
	})

	// Starts all the shared informers that have been created by the factory so
	// far.

	informerFactory.Start(o.stop)

	// wait for the initial synchronization of the local cache
	if !cache.WaitForCacheSync(o.stop, eventInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for event caches to sync"))
	}
	if !cache.WaitForCacheSync(o.stop, podInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for pod caches to sync"))
	}
	o.IsReady.Store(true)

	<-o.stop

	// Wait forever
	select {}
}

func (o *Options) OnEvent(e *v1.Event, namespace string) {
	if e.InvolvedObject.Kind != "Pod" {
		return
	}
	if e.Message != ErrImagePullMessage && e.Message != ErrImagePullBackOffMessage {
		log.Logger().Debugf("ignoring pod message %s", e.Message)
		return
	}

	ns := e.InvolvedObject.Namespace
	if ns == "" {
		ns = namespace
	}
	name := e.InvolvedObject.Name
	log.Logger().Infof("found pod %s with message %s", name, e.Message)

	ctx := context.TODO()
	err := o.KubeClient.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		log.Logger().Errorf("failed to delete Pod %s in namespace %s : %s", name, ns, err.Error())
		return
	}

	log.Logger().Infof("deleted pod %s in namespace %s", name, ns)
}

func (o *Options) OnPod(p *v1.Pod) {
	name := p.Name
	if pods.IsPodReady(p) {
		o.readyPods[name] = true
	} else {
		delete(o.readyPods, name)
	}

	count := len(o.readyPods)
	if count < o.PodCount {
		return
	}

	log.Logger().Infof("has %d ready pods now", count)
	os.Exit(0)
}
