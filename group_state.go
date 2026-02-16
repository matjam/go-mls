package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// pendingProposal marshal/unmarshal — these don't exist in the original code.

func (pp *pendingProposal) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(pp.ref))
	pp.proposal.marshal(b)
	b.AddUint32(uint32(pp.sender))
}

func (pp *pendingProposal) unmarshal(s *cryptobyte.String) error {
	*pp = pendingProposal{}

	if !readOpaqueVec(s, (*[]byte)(&pp.ref)) {
		return io.ErrUnexpectedEOF
	}

	pp.proposal = new(proposal)
	if err := pp.proposal.unmarshal(s); err != nil {
		return err
	}

	if !s.ReadUint32((*uint32)(&pp.sender)) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

// groupState is an intermediate type used to marshal/unmarshal a Group.
type groupState struct {
	groupContext           groupContext
	tree                   ratchetTree
	interimTranscriptHash  []byte
	pskSecret              []byte
	epochSecret            []byte
	initSecret             []byte
	myLeafIndex            leafIndex
	privTree               []hpkePrivateKey
	signaturePriv          signaturePrivateKey
	pendingProposals       []pendingProposal
}

func (gs *groupState) marshal(b *cryptobyte.Builder) {
	gs.groupContext.marshal(b)
	gs.tree.marshal(b)
	writeOpaqueVec(b, gs.interimTranscriptHash)
	writeOpaqueVec(b, gs.pskSecret)
	writeOpaqueVec(b, gs.epochSecret)
	writeOpaqueVec(b, gs.initSecret)
	b.AddUint32(uint32(gs.myLeafIndex))

	// privTree: vector of optional opaqueVec entries
	writeVector(b, len(gs.privTree), func(b *cryptobyte.Builder, i int) {
		key := gs.privTree[i]
		writeOptional(b, key != nil)
		if key != nil {
			writeOpaqueVec(b, []byte(key))
		}
	})

	writeOpaqueVec(b, []byte(gs.signaturePriv))

	// pendingProposals
	writeVector(b, len(gs.pendingProposals), func(b *cryptobyte.Builder, i int) {
		gs.pendingProposals[i].marshal(b)
	})
}

func (gs *groupState) unmarshal(s *cryptobyte.String) error {
	*gs = groupState{}

	if err := gs.groupContext.unmarshal(s); err != nil {
		return fmt.Errorf("unmarshal group context: %w", err)
	}

	if err := gs.tree.unmarshal(s); err != nil {
		return fmt.Errorf("unmarshal ratchet tree: %w", err)
	}

	if !readOpaqueVec(s, &gs.interimTranscriptHash) {
		return io.ErrUnexpectedEOF
	}
	if !readOpaqueVec(s, &gs.pskSecret) {
		return io.ErrUnexpectedEOF
	}
	if !readOpaqueVec(s, &gs.epochSecret) {
		return io.ErrUnexpectedEOF
	}
	if !readOpaqueVec(s, &gs.initSecret) {
		return io.ErrUnexpectedEOF
	}

	if !s.ReadUint32((*uint32)(&gs.myLeafIndex)) {
		return io.ErrUnexpectedEOF
	}

	// privTree
	err := readVector(s, func(s *cryptobyte.String) error {
		var present bool
		if !readOptional(s, &present) {
			return io.ErrUnexpectedEOF
		}
		if present {
			var key []byte
			if !readOpaqueVec(s, &key) {
				return io.ErrUnexpectedEOF
			}
			gs.privTree = append(gs.privTree, hpkePrivateKey(key))
		} else {
			gs.privTree = append(gs.privTree, nil)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("unmarshal priv tree: %w", err)
	}

	var sigPriv []byte
	if !readOpaqueVec(s, &sigPriv) {
		return io.ErrUnexpectedEOF
	}
	gs.signaturePriv = signaturePrivateKey(sigPriv)

	// pendingProposals
	err = readVector(s, func(s *cryptobyte.String) error {
		var pp pendingProposal
		if err := pp.unmarshal(s); err != nil {
			return err
		}
		gs.pendingProposals = append(gs.pendingProposals, pp)
		return nil
	})
	if err != nil {
		return fmt.Errorf("unmarshal pending proposals: %w", err)
	}

	return nil
}

// Marshal serializes the Group state for persistence.
func (g *Group) Marshal() ([]byte, error) {
	gs := groupState{
		groupContext:          g.groupContext,
		tree:                  g.tree,
		interimTranscriptHash: g.interimTranscriptHash,
		pskSecret:             g.pskSecret,
		epochSecret:           g.epochSecret,
		initSecret:            g.initSecret,
		myLeafIndex:           g.myLeafIndex,
		privTree:              g.privTree,
		signaturePriv:         g.signaturePriv,
		pendingProposals:      g.pendingProposals,
	}
	return marshal(&gs)
}

// UnmarshalGroupState restores a Group from bytes produced by Marshal.
func UnmarshalGroupState(data []byte) (*Group, error) {
	var gs groupState
	if err := unmarshal(data, &gs); err != nil {
		return nil, fmt.Errorf("unmarshal group state: %w", err)
	}

	return &Group{
		groupContext:          gs.groupContext,
		tree:                  gs.tree,
		interimTranscriptHash: gs.interimTranscriptHash,
		pskSecret:             gs.pskSecret,
		epochSecret:           gs.epochSecret,
		initSecret:            gs.initSecret,
		myLeafIndex:           gs.myLeafIndex,
		privTree:              gs.privTree,
		signaturePriv:         gs.signaturePriv,
		pendingProposals:      gs.pendingProposals,
	}, nil
}
