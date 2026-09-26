package p2p

import (
	"fmt"
	"sort"
)

type NAT3Mapping struct {
	Server   string
	Address  string
	Port     uint16
	Protocol string
}

type NAT3Assessment struct {
	Observations []NAT3Mapping

	PublicAddress string

	SameAddress bool
	StablePort  bool

	MinPort    uint16
	MaxPort    uint16
	PortSpread uint16
}

func AssessNAT3Observations(
	observations []ReflexiveObservation,
) NAT3Assessment {

	result := NAT3Assessment{
		Observations: make([]NAT3Mapping, 0, len(observations)),
	}

	if len(observations) == 0 {
		return result
	}

	unique := make(map[string]NAT3Mapping)

	for _, observation := range observations {
		if observation.Address == "" || observation.Port == 0 {
			continue
		}

		mapping := NAT3Mapping{
			Server:   observation.Server,
			Address:  observation.Address,
			Port:     observation.Port,
			Protocol: observation.Protocol,
		}

		key := fmt.Sprintf(
			"%s|%s|%d|%s",
			mapping.Server,
			mapping.Address,
			mapping.Port,
			mapping.Protocol,
		)

		if _, exists := unique[key]; exists {
			continue
		}

		unique[key] = mapping
		result.Observations = append(
			result.Observations,
			mapping,
		)
	}

	if len(result.Observations) == 0 {
		return result
	}

	sort.SliceStable(
		result.Observations,
		func(i, j int) bool {
			return result.Observations[i].Server <
				result.Observations[j].Server
		},
	)

	result.PublicAddress = result.Observations[0].Address
	result.SameAddress = true

	minPort := result.Observations[0].Port
	maxPort := result.Observations[0].Port

	for _, observation := range result.Observations {
		if observation.Address != result.PublicAddress {
			result.SameAddress = false
		}

		if observation.Port < minPort {
			minPort = observation.Port
		}

		if observation.Port > maxPort {
			maxPort = observation.Port
		}
	}

	result.MinPort = minPort
	result.MaxPort = maxPort
	result.PortSpread = maxPort - minPort

	result.StablePort = result.SameAddress &&
		result.PortSpread == 0

	return result
}

func DiscoverNAT3Assessment() NAT3Assessment {
	observations := DiscoverReflexiveObservations()
	return AssessNAT3Observations(observations)
}

func NAT3Diagnostics(
	assessment NAT3Assessment,
) string {

	if len(assessment.Observations) == 0 {
		return "NAT3: no reflexive observations available"
	}

	if !assessment.SameAddress {
		return fmt.Sprintf(
			"NAT3: %d observations, public address varies across STUN servers",
			len(assessment.Observations),
		)
	}

	if assessment.StablePort {
		return fmt.Sprintf(
			"NAT3: %d observations, public=%s, UDP mapping port stable=%d",
			len(assessment.Observations),
			assessment.PublicAddress,
			assessment.MinPort,
		)
	}

	return fmt.Sprintf(
		"NAT3: %d observations, public=%s, UDP mapping port varies=%d..%d spread=%d",
		len(assessment.Observations),
		assessment.PublicAddress,
		assessment.MinPort,
		assessment.MaxPort,
		assessment.PortSpread,
	)
}
