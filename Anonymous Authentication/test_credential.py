from inspect import Signature
import os
import random
import pytest

from typing import Any, List, Tuple
from serialization import jsonpickle

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT

from credential import *

MAX_N = 5


def test_generate_key():
  """CASE: valid attributes list"""

  attributes = [G1.order().random() for _ in range(MAX_N)]
  sk, pk = generate_key(attributes)

  assert isinstance(sk, SecretKey)
  assert isinstance(pk, PublicKey)

  print("KeyGen test passed")



def test_generate_key_fail_case1():
  """CASE: empty attributes list -> raise ValuaError"""

  attributes = list()
  sk, pk = generate_key(attributes)

  assert False, "Attributes should be greater than 1"


def test_generate_key_fail_case2():
  """CASE: negative Bn object -> raise TypeError"""

  attributes = [G1.order().random() for _ in range(MAX_N)]

  sk, pk = generate_key(attributes)
  assert False, "All attributes should be Bn positive objects"


def test_sign():
  """CASE: valid sign and verify success"""

  attributes = [G1.order().random() for _ in range(MAX_N)]

  sk, pk = generate_key(attributes)
  msgs = bn_list_to_bytes_list(attributes)
  signature = sign(sk, msgs)

  assert isinstance(signature, Signature)

  print("Sign test passed")

  assert verify(pk, signature, msgs), "verify failed"

  print("Verify test passed")



def test_sign_fail_case1():
  """CASE1: sigma1 or sigma2 is a unity element in G1 """

  attributes = [G1.order().random() for _ in range(MAX_N)]
  sk, pk = generate_key(attributes)
  msgs = bn_list_to_bytes_list(attributes)

  assert verify(pk, Signature(G1.unity(), G1.unity()), msgs) != False, "sigma1 or sigma2 is a unity element in G1"
  

def test_sign_fail_case2():
  """ CASE2: verify failed """

  attributes1 = [G1.order().random() for _ in range(MAX_N)]
  attributes2 = [G1.order().random() for _ in range(MAX_N)]
  sk1, pk1 = generate_key(attributes1)
  sk2, pk2 = generate_key(attributes1)
  msgs = bn_list_to_bytes_list(attributes1)

  signature = sign(sk1, msgs)

  assert isinstance(signature, Signature)

  assert verify(pk2, signature, msgs) != False, "verify failed"



def test_create_issue_request():
  """CASE: check if the issue_request contained the proof is correctly generated"""

  attributes = [G1.order().random() for _ in range(MAX_N)]
  user_attributes, issuer_attributes = randomly_split_attributes(attributes)
  sk, pk = generate_key(attributes)

  issue_request, state = create_issue_request(pk, user_attributes)

  assert isinstance(issue_request, IssueRequest)
  assert isinstance(issue_request.pi, PedersenKnowledgeProof)

  print("Create issue test passed")



def test_sign_issue_request():
  """CASE: check if the proof provided by prover is valid and verify the signature"""
  
  attributes = [G1.order().random() for _ in range(2 * MAX_N)]
  sk, pk = generate_key(attributes)

  user_attributes = {i + 1: attr for i, attr in enumerate(attributes[:MAX_N])}
  issuer_attributes = {i + len(user_attributes) + 1: attr for i, attr in enumerate(attributes[MAX_N:])}

  issue_request, state = create_issue_request(pk, user_attributes)

  assert isinstance(issue_request, IssueRequest)
  assert isinstance(issue_request.pi, PedersenKnowledgeProof)

  blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)

  assert isinstance(blind_signature, BlindSignature)

  print("Sign issue request test passed")



def test_obtain_credential():
  """CASE: check if the signature on the given attributes is valid. If valid, generate the final signature """

  attributes = [G1.order().random() for _ in range(2 * MAX_N)]
  sk, pk = generate_key(attributes)

  user_attributes = {i + 1: attr for i, attr in enumerate(attributes[:MAX_N])}
  issuer_attributes = {i + len(user_attributes) + 1: attr for i, attr in enumerate(attributes[MAX_N:])}

  issue_request, state = create_issue_request(pk, user_attributes)

  assert isinstance(issue_request, IssueRequest)
  assert isinstance(issue_request.pi, PedersenKnowledgeProof)

  blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)

  assert isinstance(blind_signature, BlindSignature)

  credential = obtain_credential(pk, blind_signature, state)

  assert isinstance(credential, AnonymousCredential)

  print("Obtain credential test passed")



def test_create_plus_verify_disclosure_proof():
  """CASE: check if the user possess the valid credential"""

  attributes = [G1.order().random() for _ in range(2 * MAX_N)]
  sk, pk = generate_key(attributes)

  user_attributes = {i + 1: attr for i, attr in enumerate(attributes[:MAX_N])}
  issuer_attributes = {i + len(user_attributes) + 1: attr for i, attr in enumerate(attributes[MAX_N:])}

  issue_request, state = create_issue_request(pk, user_attributes)

  assert isinstance(issue_request, IssueRequest)
  assert isinstance(issue_request.pi, PedersenKnowledgeProof)

  blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)

  assert isinstance(blind_signature, BlindSignature)

  credential = obtain_credential(pk, blind_signature, state)

  assert isinstance(credential, AnonymousCredential)

  shuffled_attributes = random.sample(attributes, len(attributes))

  hidden_attributes = {i + 1: attr for i, attr in enumerate(attributes[:MAX_N])}
  disclosed_attributes = {i + len(user_attributes) + 1: attr for i, attr in enumerate(attributes[MAX_N:])}
  
  msg = os.urandom(12)

  disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, msg)

  assert isinstance(disclosure_proof, DisclosureProof)

  print("Create disclosure proof test passed")

  assert verify_disclosure_proof(pk, disclosure_proof, disclosed_attributes, msg), "verify failed"

  print("Verify disclosure proof test passed")





####################################
## TOOLS METHODS FOR COMPUTATIONS ##
####################################


def randomly_split_attributes(
    attributes: List[Attribute],
) -> Tuple[AttributeMap, AttributeMap]:
    """From the list of all attributes, split in 2 lists of indices mapped to their related attribute"""
    L = len(attributes)
    # creates shuffled dict with keys in [1,L]
    shuffled_attributes = list(map(lambda i: (i[0] + 1, i[1]), enumerate(attributes)))
    random.shuffle(shuffled_attributes)
    split_index = random.randint(0, L)
    user_attributes = dict(shuffled_attributes[:split_index])
    issuer_attributes = dict(shuffled_attributes[split_index:])

    return user_attributes, issuer_attributes


  

