package tls

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/jenkins-x-plugins/jx-verify/pkg/rootcmd"
	"github.com/jenkins-x/jx-logging/v3/pkg/log"

	"github.com/pkg/errors"

	"github.com/genkiroid/cert"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/helper"
	"github.com/jenkins-x/jx-helpers/v3/pkg/cobras/templates"
	"github.com/spf13/cobra"
)

var (
	cmdLong = templates.LongDesc(`
		Verifies a TLS certificate, useful to ensure a HTTPS endpoint is
		using a certificate issued by a specific issuer like LetsEncrypt
`)

	cmdExample = templates.Examples(`
		# verifies a TLS certificate issuer and subject
		%s step verify tls hook.foo.bar.com --insecure --issuer 'CN=(STAGING) Artificial Apricot R3' --subject 'CN=*.foo.bar.com'
	`)
)

const (
	CertificateIssuerFakeLE = "(STAGING) Artificial Apricot R3"
	CertificateIssuerProdLE = "R3"
)

// Options the options for verifying TLS certs
type Options struct {
	production bool
	timeout    time.Duration
	issuer     string
}

// NewCmdVerifyTLS creates a command object for the command
func NewCmdVerifyTLS() (*cobra.Command, *Options) {
	o := &Options{}

	cmd := &cobra.Command{
		Use:     "tls [url]",
		Aliases: []string{"cert"},
		Short:   "Verifies TLS for a Cluster",
		Long:    cmdLong,
		Example: fmt.Sprintf(cmdExample, rootcmd.BinaryName),
		Run: func(cmd *cobra.Command, args []string) {
			err := o.Run(args)
			helper.CheckErr(err)
		},
	}

	cmd.Flags().StringVarP(&o.issuer, "issuer", "", "", "override the default issuer to match the TLS certificate to")
	cmd.Flags().BoolVarP(&o.production, "production", "", true, "override the detection of whether to verify TLS is using Production or Staging LetsEncrypt service")
	cmd.Flags().DurationVarP(&o.timeout, "timeout", "t", 10*time.Minute, "timeout")

	return cmd, o
}

// Run implements the command
func (o *Options) Run(args []string) error {
	if len(args) != 1 {
		return errors.Errorf("domain command argument not specified")
	}

	err := retry(o.timeout, func() error {
		return o.verifyCert(args)
	}, func(e error, d time.Duration) {
		log.Logger().Infof("resolution failed, backing of for %s", d)
	})
	if err != nil {
		return errors.Wrap(err, "unable to resolve TLS, check certmanager Issuer and Certificate resources are Ready.  kubectl get issuer,certificate")
	}

	return nil
}

func (o *Options) verifyCert(args []string) error {
	cert.SkipVerify = !o.production
	certs, err := cert.NewCerts(args)
	if err != nil {
		return errors.Wrapf(err, "failed to get domain [%s] certificate information", args[0])
	}

	issuer := o.issuer
	if issuer == "" {
		if o.production {
			issuer = CertificateIssuerProdLE
		} else {
			issuer = CertificateIssuerFakeLE
		}
	}

	for _, certificate := range certs {
		if certificate.Issuer == issuer {
			log.Logger().Infof("matched issuer %s", issuer)
			return nil
		}
	}
	return fmt.Errorf("no matching issuer %s found", issuer)
}

// retry retries with exponential backoff the given function
func retry(maxElapsedTime time.Duration, f func() error, n func(error, time.Duration)) error {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = maxElapsedTime
	bo.InitialInterval = 2 * time.Second
	bo.MaxInterval = 10 * time.Second
	bo.Reset()
	return backoff.RetryNotify(f, bo, n)
}
