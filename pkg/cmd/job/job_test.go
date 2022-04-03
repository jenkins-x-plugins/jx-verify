package job_test

import (
	"testing"

	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/job"
	"k8s.io/client-go/kubernetes/fake"
)

func TestVerifyJob(t *testing.T) {
	ns := "jx"
	_, o := job.NewCmdVerifyJob()
	kubeClient := fake.NewSimpleClientset()
	o.KubeClient = kubeClient
	o.Namespace = ns

	// TODO
}
