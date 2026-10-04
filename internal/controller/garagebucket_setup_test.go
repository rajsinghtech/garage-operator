/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// informerRecorder wraps the manager cache and records every kind an
// informer is requested for. An informer for a kind means the operator
// lists/watches it cluster-wide, which needs RBAC for that resource.
type informerRecorder struct {
	cache.Cache
	mu    sync.Mutex
	kinds map[schema.GroupKind]struct{}
}

func (c *informerRecorder) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	c.note(obj)
	return c.Cache.GetInformer(ctx, obj, opts...)
}

func (c *informerRecorder) note(obj client.Object) {
	gvk, err := apiutil.GVKForObject(obj, k8sClient.Scheme())
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kinds[gvk.GroupKind()] = struct{}{}
}

func (c *informerRecorder) has(gk schema.GroupKind) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.kinds[gk]
	return ok
}

var _ = Describe("GarageBucketReconciler.SetupWithManager Ingress gating", func() {
	var (
		ingressGK = schema.GroupKind{Group: "networking.k8s.io", Kind: "Ingress"}
		bucketGK  = schema.GroupKind{Group: "garage.rajsingh.info", Kind: "GarageBucket"}
	)

	// startManager runs a real manager against envtest with the bucket
	// controller and returns the recorder once the controller's primary
	// (GarageBucket) informer has been requested, i.e. the controller started.
	startManager := func(enableIngress bool) *informerRecorder {
		rec := &informerRecorder{kinds: map[schema.GroupKind]struct{}{}}
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 k8sClient.Scheme(),
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Controller:             ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
			NewCache: func(c *rest.Config, opts cache.Options) (cache.Cache, error) {
				inner, err := cache.New(c, opts)
				if err != nil {
					return nil, err
				}
				rec.Cache = inner
				return rec, nil
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect((&GarageBucketReconciler{
			Client:        mgr.GetClient(),
			Scheme:        mgr.GetScheme(),
			EnableIngress: enableIngress,
		}).SetupWithManager(mgr)).To(Succeed())

		mgrCtx, stop := context.WithCancel(ctx)
		DeferCleanup(stop)
		go func() {
			defer GinkgoRecover()
			_ = mgr.Start(mgrCtx)
		}()
		Eventually(func() bool { return rec.has(bucketGK) }, 30*time.Second, 100*time.Millisecond).Should(BeTrue())
		// Sources start in registration order; give an Owns() source the
		// chance to register before asserting its absence.
		time.Sleep(2 * time.Second)
		return rec
	}

	It("starts no Ingress informer unless --enable-ingress is set", func() {
		rec := startManager(false)
		Expect(rec.has(ingressGK)).To(BeFalse(), "an Ingress informer needs cluster-wide list/watch RBAC")
	})

	It("watches owned Ingresses when --enable-ingress is set", func() {
		rec := startManager(true)
		Expect(rec.has(ingressGK)).To(BeTrue())
	})
})
