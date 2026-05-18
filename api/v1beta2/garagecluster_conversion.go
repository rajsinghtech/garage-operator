/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

// Hub marks GarageCluster as the conversion hub for the
// garage.rajsingh.info group. v1beta1 GarageCluster CRs converted into this
// type before the controller reads them. See
// api/v1beta1/garagecluster_conversion.go for the bidirectional logic.
func (*GarageCluster) Hub() {}
