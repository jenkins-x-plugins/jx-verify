package cmd

import (
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/ctx"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/ingress"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/install"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/job"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/pods"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/tls"
	"github.com/jenkins-x-plugins/jx-verify/pkg/cmd/version"
	"github.com/jenkins-x-plugins/jx-verify/pkg/rootcmd"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"
	"github.com/spf13/cobra"
)

// Main creates the new command
func Main() *cobra.Command {
	cmd := &cobra.Command{
		Annotations: map[string]string{
			cobra.CommandDisplayNameAnnotation: rootcmd.TopLevelCommand,
		},
		Short: "commands for verifying Jenkins X environments",
		Run: func(cmd *cobra.Command, _ []string) {
			err := cmd.Help()
			if err != nil {
				log.Logger().Error(err)
			}
		},
	}
	cmd.AddCommand(cobras.SplitCommand(ctx.NewCmdVerifyContext()))
	cmd.AddCommand(cobras.SplitCommand(ingress.NewCmdVerifyIngress()))
	cmd.AddCommand(cobras.SplitCommand(install.NewCmdVerifyInstall()))
	cmd.AddCommand(cobras.SplitCommand(job.NewCmdVerifyJob()))
	cmd.AddCommand(cobras.SplitCommand(pods.NewCmdVerifyPods()))
	cmd.AddCommand(cobras.SplitCommand(tls.NewCmdVerifyTLS()))
	cmd.AddCommand(cobras.SplitCommand(version.NewCmdVersion()))

	return cmd
}
