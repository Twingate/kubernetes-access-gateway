// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"maps"

	"github.com/google/uuid"
)

// sshContext carries connection-level SSH metadata for audit logging.
type sshContext struct {
	id            string
	clientVersion string
	serverVersion string
}

func (s *sshContext) baseFields() map[string]any {
	return map[string]any{
		"id":             s.id,
		"client_version": s.clientVersion,
		"server_version": s.serverVersion,
	}
}

func (s *sshContext) withGlobalRequest(reqType, source, target string) map[string]any {
	m := s.baseFields()
	m["global_request"] = map[string]any{
		"type":   reqType,
		"source": source,
		"target": target,
	}

	return m
}

func (s *sshContext) withConnectionClose(channelsOpened int) map[string]any {
	m := s.baseFields()
	m["channels_opened"] = channelsOpened

	return m
}

// sshChannelContext carries channel-level SSH metadata for audit logging.
type sshChannelContext struct {
	*sshContext

	channelID   string
	channelType string
	sourceLabel string
	targetLabel string
}

func newSSHChannelContext(sshCtx *sshContext, channelType, sourceLabel, targetLabel string) *sshChannelContext {
	return &sshChannelContext{
		sshContext:  sshCtx,
		channelID:   uuid.New().String(),
		channelType: channelType,
		sourceLabel: sourceLabel,
		targetLabel: targetLabel,
	}
}

func (c *sshChannelContext) baseFields() map[string]any {
	m := c.sshContext.baseFields()
	m["channel"] = map[string]any{
		"id":     c.channelID,
		"type":   c.channelType,
		"source": c.sourceLabel,
		"target": c.targetLabel,
	}

	return m
}

func (c *sshChannelContext) withRequest(reqType string, reqExtra map[string]any) map[string]any {
	m := c.baseFields()

	req := map[string]any{
		"type":   reqType,
		"source": c.sourceLabel,
		"target": c.targetLabel,
	}

	maps.Copy(req, reqExtra)

	m["request"] = req

	return m
}
