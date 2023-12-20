// Copyright IBM Corp. All Rights Reserved.
// Copyright 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.22.3
// source: fpc/trusted_ledger.proto

package protos

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// public metadata get_state_metadata(
//
//	const char *namespace,
//	const char *key);
type GetMetadataRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Key       string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *GetMetadataRequest) Reset() {
	*x = GetMetadataRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMetadataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMetadataRequest) ProtoMessage() {}

func (x *GetMetadataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMetadataRequest.ProtoReflect.Descriptor instead.
func (*GetMetadataRequest) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{0}
}

func (x *GetMetadataRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *GetMetadataRequest) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

type GetMetadataResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *GetMetadataResponse) Reset() {
	*x = GetMetadataResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMetadataResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMetadataResponse) ProtoMessage() {}

func (x *GetMetadataResponse) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMetadataResponse.ProtoReflect.Descriptor instead.
func (*GetMetadataResponse) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{1}
}

func (x *GetMetadataResponse) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

// public metadata get_multi_state_metadata(
//
//	const char *namespace,
//	const char *comp_key);
type GetMultiMetadataRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	CompoKey  string `protobuf:"bytes,2,opt,name=compo_key,json=compoKey,proto3" json:"compo_key,omitempty"`
}

func (x *GetMultiMetadataRequest) Reset() {
	*x = GetMultiMetadataRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMultiMetadataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMultiMetadataRequest) ProtoMessage() {}

func (x *GetMultiMetadataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMultiMetadataRequest.ProtoReflect.Descriptor instead.
func (*GetMultiMetadataRequest) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{2}
}

func (x *GetMultiMetadataRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *GetMultiMetadataRequest) GetCompoKey() string {
	if x != nil {
		return x.CompoKey
	}
	return ""
}

type GetMultiMetadataResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// SHA-256 over value found by key (or all-zero if key absent)
	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *GetMultiMetadataResponse) Reset() {
	*x = GetMultiMetadataResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMultiMetadataResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMultiMetadataResponse) ProtoMessage() {}

func (x *GetMultiMetadataResponse) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMultiMetadataResponse.ProtoReflect.Descriptor instead.
func (*GetMultiMetadataResponse) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{3}
}

func (x *GetMultiMetadataResponse) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

// verify that a given identity is part of a msp
// the input is a serialized identity proto message as defined in
// https://github.com/hyperledger/fabric-protos/blob/main/msp/identities.proto#L15
//
//	public bool validate_identity(
//	        const uint8_t *serializedIdentity,
//	        const uint32_t len);
type ValidateIdentityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SerializedIdentity []byte `protobuf:"bytes,1,opt,name=serialized_identity,json=serializedIdentity,proto3" json:"serialized_identity,omitempty"`
}

func (x *ValidateIdentityRequest) Reset() {
	*x = ValidateIdentityRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidateIdentityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidateIdentityRequest) ProtoMessage() {}

func (x *ValidateIdentityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidateIdentityRequest.ProtoReflect.Descriptor instead.
func (*ValidateIdentityRequest) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{4}
}

func (x *ValidateIdentityRequest) GetSerializedIdentity() []byte {
	if x != nil {
		return x.SerializedIdentity
	}
	return nil
}

type ValidateIdentityResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsValid bool `protobuf:"varint,1,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
}

func (x *ValidateIdentityResponse) Reset() {
	*x = ValidateIdentityResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidateIdentityResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidateIdentityResponse) ProtoMessage() {}

func (x *ValidateIdentityResponse) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidateIdentityResponse.ProtoReflect.Descriptor instead.
func (*ValidateIdentityResponse) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{5}
}

func (x *ValidateIdentityResponse) GetIsValid() bool {
	if x != nil {
		return x.IsValid
	}
	return false
}

// checks if a given enclave identifier can endorse transactions
// as defined in the chaincode definition; this checks that the given enclave
// has correct the MRENCLAVE and enclave is part of an organization that can
// satisfy the endorsing policy of a given chaincode.
//
//	public bool can_endorse(
//	        const char *chaincode_id,
//	        const char *enclave_id);
type CanEndorseRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// note: could be implied from session context but still explicit in case we want to expose to ERCC
	ChaincodeId string `protobuf:"bytes,1,opt,name=chaincode_id,json=chaincodeId,proto3" json:"chaincode_id,omitempty"`
	EnclaveId   string `protobuf:"bytes,2,opt,name=enclave_id,json=enclaveId,proto3" json:"enclave_id,omitempty"`
}

func (x *CanEndorseRequest) Reset() {
	*x = CanEndorseRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CanEndorseRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CanEndorseRequest) ProtoMessage() {}

func (x *CanEndorseRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CanEndorseRequest.ProtoReflect.Descriptor instead.
func (*CanEndorseRequest) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{6}
}

func (x *CanEndorseRequest) GetChaincodeId() string {
	if x != nil {
		return x.ChaincodeId
	}
	return ""
}

func (x *CanEndorseRequest) GetEnclaveId() string {
	if x != nil {
		return x.EnclaveId
	}
	return ""
}

type CanEndorseResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsValid bool `protobuf:"varint,1,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
}

func (x *CanEndorseResponse) Reset() {
	*x = CanEndorseResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CanEndorseResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CanEndorseResponse) ProtoMessage() {}

func (x *CanEndorseResponse) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CanEndorseResponse.ProtoReflect.Descriptor instead.
func (*CanEndorseResponse) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{7}
}

func (x *CanEndorseResponse) GetIsValid() bool {
	if x != nil {
		return x.IsValid
	}
	return false
}

// - wrapper type which is passed to `tl_session_request` and the handler registered with `tl_session_register`
type Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TxContext []byte `protobuf:"bytes,1,opt,name=tx_context,json=txContext,proto3" json:"tx_context,omitempty"`
	// tx_context is used by TLCC to enforce consistency across separate requests of
	// a single chaincode transaction (including potential subtransactions) and is
	// an arbitrary identifier chosen by ECC_Enclave with following constraints:
	//   - for a given single (top-level) chaincode invocation, it must be the same for any tlcc requests
	//     triggered by it (whether directly the top-level or from sub-transactions invoked via cc2cc)
	//   - different (top-level) invocations (of same chaincode) must provide different identifiers
	//
	// Based on this tlcc can achieve view consistency by, e.g., serializing transactions and state
	// updates or keeping separate views, with each active transaction identifiers mapped to one of
	// these views.
	// Note: If TLCC manages snapshots by serializing, we might also have to add an additional
	// Request/Response type notify tlcc when an chaincode invocation has completed (otherwise
	// TLCC wouldn't know when it would be safe to start the state update
	//
	// An alternative approach could be to replace this field with some view identifier
	// in TLCCResponse, with ECC enforcing consistency (although in this case it could
	// only abort in case of inconsistency and there might be the issue that as parallelism
	// increases, no progress could ever be made ...
	// =>
	// TODO: Above has to be reconciled with the resolution of following issues/PRs
	//
	//	related to view consistency:
	//	- [#402](https://github.com/hyperledger/fabric-private-chaincode/issues/402)
	//	- [#435](https://github.com/hyperledger/fabric-private-chaincode/pull/435)
	//	- [#361](https://github.com/hyperledger/fabric-private-chaincode/issues/361)
	//
	// Types that are assignable to Request:
	//
	//	*Request_Metadata
	//	*Request_MultiMetadata
	//	*Request_ValidateIdentity
	//	*Request_CanEndorse
	Request isRequest_Request `protobuf_oneof:"request"`
}

func (x *Request) Reset() {
	*x = Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request.ProtoReflect.Descriptor instead.
func (*Request) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{8}
}

func (x *Request) GetTxContext() []byte {
	if x != nil {
		return x.TxContext
	}
	return nil
}

func (m *Request) GetRequest() isRequest_Request {
	if m != nil {
		return m.Request
	}
	return nil
}

func (x *Request) GetMetadata() *GetMetadataRequest {
	if x, ok := x.GetRequest().(*Request_Metadata); ok {
		return x.Metadata
	}
	return nil
}

func (x *Request) GetMultiMetadata() *GetMultiMetadataRequest {
	if x, ok := x.GetRequest().(*Request_MultiMetadata); ok {
		return x.MultiMetadata
	}
	return nil
}

func (x *Request) GetValidateIdentity() *ValidateIdentityRequest {
	if x, ok := x.GetRequest().(*Request_ValidateIdentity); ok {
		return x.ValidateIdentity
	}
	return nil
}

func (x *Request) GetCanEndorse() *CanEndorseRequest {
	if x, ok := x.GetRequest().(*Request_CanEndorse); ok {
		return x.CanEndorse
	}
	return nil
}

type isRequest_Request interface {
	isRequest_Request()
}

type Request_Metadata struct {
	Metadata *GetMetadataRequest `protobuf:"bytes,2,opt,name=metadata,proto3,oneof"`
}

type Request_MultiMetadata struct {
	MultiMetadata *GetMultiMetadataRequest `protobuf:"bytes,3,opt,name=multi_metadata,json=multiMetadata,proto3,oneof"`
}

type Request_ValidateIdentity struct {
	ValidateIdentity *ValidateIdentityRequest `protobuf:"bytes,4,opt,name=validate_identity,json=validateIdentity,proto3,oneof"`
}

type Request_CanEndorse struct {
	CanEndorse *CanEndorseRequest `protobuf:"bytes,5,opt,name=can_endorse,json=canEndorse,proto3,oneof"`
}

func (*Request_Metadata) isRequest_Request() {}

func (*Request_MultiMetadata) isRequest_Request() {}

func (*Request_ValidateIdentity) isRequest_Request() {}

func (*Request_CanEndorse) isRequest_Request() {}

type Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Response:
	//
	//	*Response_Metadata
	//	*Response_MultiMetadata
	//	*Response_ValidateIdentity
	//	*Response_CanEndorse
	Response isResponse_Response `protobuf_oneof:"response"`
}

func (x *Response) Reset() {
	*x = Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fpc_trusted_ledger_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_fpc_trusted_ledger_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_fpc_trusted_ledger_proto_rawDescGZIP(), []int{9}
}

func (m *Response) GetResponse() isResponse_Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (x *Response) GetMetadata() *GetMetadataResponse {
	if x, ok := x.GetResponse().(*Response_Metadata); ok {
		return x.Metadata
	}
	return nil
}

func (x *Response) GetMultiMetadata() *GetMultiMetadataResponse {
	if x, ok := x.GetResponse().(*Response_MultiMetadata); ok {
		return x.MultiMetadata
	}
	return nil
}

func (x *Response) GetValidateIdentity() *ValidateIdentityResponse {
	if x, ok := x.GetResponse().(*Response_ValidateIdentity); ok {
		return x.ValidateIdentity
	}
	return nil
}

func (x *Response) GetCanEndorse() *CanEndorseResponse {
	if x, ok := x.GetResponse().(*Response_CanEndorse); ok {
		return x.CanEndorse
	}
	return nil
}

type isResponse_Response interface {
	isResponse_Response()
}

type Response_Metadata struct {
	Metadata *GetMetadataResponse `protobuf:"bytes,1,opt,name=metadata,proto3,oneof"`
}

type Response_MultiMetadata struct {
	MultiMetadata *GetMultiMetadataResponse `protobuf:"bytes,2,opt,name=multi_metadata,json=multiMetadata,proto3,oneof"`
}

type Response_ValidateIdentity struct {
	ValidateIdentity *ValidateIdentityResponse `protobuf:"bytes,3,opt,name=validate_identity,json=validateIdentity,proto3,oneof"`
}

type Response_CanEndorse struct {
	CanEndorse *CanEndorseResponse `protobuf:"bytes,4,opt,name=can_endorse,json=canEndorse,proto3,oneof"`
}

func (*Response_Metadata) isResponse_Response() {}

func (*Response_MultiMetadata) isResponse_Response() {}

func (*Response_ValidateIdentity) isResponse_Response() {}

func (*Response_CanEndorse) isResponse_Response() {}

var File_fpc_trusted_ledger_proto protoreflect.FileDescriptor

var file_fpc_trusted_ledger_proto_rawDesc = []byte{
	0x0a, 0x18, 0x66, 0x70, 0x63, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65,
	0x64, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x22, 0x44, 0x0a, 0x12, 0x47, 0x65,
	0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x22, 0x29, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x22, 0x54, 0x0a, 0x17, 0x47,
	0x65, 0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x4b, 0x65,
	0x79, 0x22, 0x2e, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73,
	0x68, 0x22, 0x4a, 0x0a, 0x17, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x13,
	0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x73, 0x65, 0x72, 0x69, 0x61,
	0x6c, 0x69, 0x7a, 0x65, 0x64, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x22, 0x35, 0x0a,
	0x18, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x69, 0x73, 0x5f,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x69, 0x73, 0x56,
	0x61, 0x6c, 0x69, 0x64, 0x22, 0x55, 0x0a, 0x11, 0x43, 0x61, 0x6e, 0x45, 0x6e, 0x64, 0x6f, 0x72,
	0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a,
	0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x49, 0x64, 0x22, 0x2f, 0x0a, 0x12, 0x43,
	0x61, 0x6e, 0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x19, 0x0a, 0x08, 0x69, 0x73, 0x5f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x07, 0x69, 0x73, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x22, 0xe5, 0x02, 0x0a,
	0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x78, 0x5f, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x74, 0x78,
	0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x40, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52,
	0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x50, 0x0a, 0x0e, 0x6d, 0x75, 0x6c,
	0x74, 0x69, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x27, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64, 0x67,
	0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0d, 0x6d, 0x75,
	0x6c, 0x74, 0x69, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x56, 0x0a, 0x11, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64,
	0x5f, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48,
	0x00, 0x52, 0x10, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x12, 0x44, 0x0a, 0x0b, 0x63, 0x61, 0x6e, 0x5f, 0x65, 0x6e, 0x64, 0x6f, 0x72,
	0x73, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74,
	0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x43, 0x61, 0x6e, 0x45, 0x6e, 0x64,
	0x6f, 0x72, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x63,
	0x61, 0x6e, 0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x22, 0xcc, 0x02, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x41, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65,
	0x64, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x12, 0x51, 0x0a, 0x0e, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x5f, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74,
	0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65,
	0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x0d, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x57, 0x0a, 0x11, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x6c, 0x65, 0x64,
	0x67, 0x65, 0x72, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x10,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x12, 0x45, 0x0a, 0x0b, 0x63, 0x61, 0x6e, 0x5f, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f,
	0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x43, 0x61, 0x6e, 0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x0a, 0x63, 0x61, 0x6e,
	0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x42, 0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x79, 0x70, 0x65, 0x72, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2f, 0x66, 0x61,
	0x62, 0x72, 0x69, 0x63, 0x2d, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2d, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_fpc_trusted_ledger_proto_rawDescOnce sync.Once
	file_fpc_trusted_ledger_proto_rawDescData = file_fpc_trusted_ledger_proto_rawDesc
)

func file_fpc_trusted_ledger_proto_rawDescGZIP() []byte {
	file_fpc_trusted_ledger_proto_rawDescOnce.Do(func() {
		file_fpc_trusted_ledger_proto_rawDescData = protoimpl.X.CompressGZIP(file_fpc_trusted_ledger_proto_rawDescData)
	})
	return file_fpc_trusted_ledger_proto_rawDescData
}

var file_fpc_trusted_ledger_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_fpc_trusted_ledger_proto_goTypes = []interface{}{
	(*GetMetadataRequest)(nil),       // 0: trusted_ledger.GetMetadataRequest
	(*GetMetadataResponse)(nil),      // 1: trusted_ledger.GetMetadataResponse
	(*GetMultiMetadataRequest)(nil),  // 2: trusted_ledger.GetMultiMetadataRequest
	(*GetMultiMetadataResponse)(nil), // 3: trusted_ledger.GetMultiMetadataResponse
	(*ValidateIdentityRequest)(nil),  // 4: trusted_ledger.ValidateIdentityRequest
	(*ValidateIdentityResponse)(nil), // 5: trusted_ledger.ValidateIdentityResponse
	(*CanEndorseRequest)(nil),        // 6: trusted_ledger.CanEndorseRequest
	(*CanEndorseResponse)(nil),       // 7: trusted_ledger.CanEndorseResponse
	(*Request)(nil),                  // 8: trusted_ledger.Request
	(*Response)(nil),                 // 9: trusted_ledger.Response
}
var file_fpc_trusted_ledger_proto_depIdxs = []int32{
	0, // 0: trusted_ledger.Request.metadata:type_name -> trusted_ledger.GetMetadataRequest
	2, // 1: trusted_ledger.Request.multi_metadata:type_name -> trusted_ledger.GetMultiMetadataRequest
	4, // 2: trusted_ledger.Request.validate_identity:type_name -> trusted_ledger.ValidateIdentityRequest
	6, // 3: trusted_ledger.Request.can_endorse:type_name -> trusted_ledger.CanEndorseRequest
	1, // 4: trusted_ledger.Response.metadata:type_name -> trusted_ledger.GetMetadataResponse
	3, // 5: trusted_ledger.Response.multi_metadata:type_name -> trusted_ledger.GetMultiMetadataResponse
	5, // 6: trusted_ledger.Response.validate_identity:type_name -> trusted_ledger.ValidateIdentityResponse
	7, // 7: trusted_ledger.Response.can_endorse:type_name -> trusted_ledger.CanEndorseResponse
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_fpc_trusted_ledger_proto_init() }
func file_fpc_trusted_ledger_proto_init() {
	if File_fpc_trusted_ledger_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_fpc_trusted_ledger_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMetadataRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMetadataResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMultiMetadataRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMultiMetadataResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidateIdentityRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidateIdentityResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CanEndorseRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CanEndorseResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fpc_trusted_ledger_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Response); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_fpc_trusted_ledger_proto_msgTypes[8].OneofWrappers = []interface{}{
		(*Request_Metadata)(nil),
		(*Request_MultiMetadata)(nil),
		(*Request_ValidateIdentity)(nil),
		(*Request_CanEndorse)(nil),
	}
	file_fpc_trusted_ledger_proto_msgTypes[9].OneofWrappers = []interface{}{
		(*Response_Metadata)(nil),
		(*Response_MultiMetadata)(nil),
		(*Response_ValidateIdentity)(nil),
		(*Response_CanEndorse)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_fpc_trusted_ledger_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_fpc_trusted_ledger_proto_goTypes,
		DependencyIndexes: file_fpc_trusted_ledger_proto_depIdxs,
		MessageInfos:      file_fpc_trusted_ledger_proto_msgTypes,
	}.Build()
	File_fpc_trusted_ledger_proto = out.File
	file_fpc_trusted_ledger_proto_rawDesc = nil
	file_fpc_trusted_ledger_proto_goTypes = nil
	file_fpc_trusted_ledger_proto_depIdxs = nil
}
