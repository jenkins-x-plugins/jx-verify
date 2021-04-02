package ctx

import (
	"fmt"

	"github.com/jenkins-x-plugins/jx-verify/pkg/rootcmd"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/jenkins-x/jx-helpers/v3/pkg/kube"
	"github.com/jenkins-x/jx-helpers/v3/pkg/options"
	"github.com/jenkins-x/jx-helpers/v3/pkg/termcolor"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	"github.com/pkg/errors"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
)

var (
	info = termcolor.ColorInfo

	cmdLong = templates.LongDesc(`
		Verifies the current kubernetes context matches a given name
`)

	cmdExample = templates.Examples(`
		# populate the pods don't have missing images
		jx verify context -c "gke_$PROJECT_ID-bdd_$REGION_$CLUSTER_NAME"

			`)
)

type Options struct {
	Context string
}

func NewCmdVerifyContext() (*cobra.Command, *Options) {
	o := &Options{}

	cmd := &cobra.Command{
		Use:     "context",
		Short:   "Verifies the current kubernetes context matches a given name",
		Long:    cmdLong,
		Aliases: []string{"ctx"},
		Example: fmt.Sprintf(cmdExample, rootcmd.BinaryName),
		Run: func(cmd *cobra.Command, args []string) {
			err := o.Run()
			helper.CheckErr(err)
		},
	}
	cmd.Flags().StringVarP(&o.Context, "context", "c", "", "The kubernetes context to match against")

	return cmd, o
}

func (o *Options) Run() error {
	if o.Context == "" {
		return options.MissingOption("context")
	}
	cfg, _, err := kube.LoadConfig()
	if err != nil {
		return errors.Wrap(err, "failed to load kubernetes config")
	}

	contextName := kube.Cluster(cfg)
	if contextName == o.Context {
		log.Logger().Infof("kubernetes context is the expected name %s", info(o.Context))
		return nil
	}

	dmp := diffmatchpatch.New()

	diffs := dmp.DiffMain(o.Context, contextName, false)

	fmt.Println()

	log.Logger().Warnf("expected kubernetes context: '%s' but was: '%s'", o.Context, contextName)
	log.Logger().Infof("\ndifference: %s\n\n", dmp.DiffPrettyText(diffs))

	return errors.Errorf("expected kubernetes context: %s but was %s", o.Context, contextName)
}
