from typing import Any, List, Tuple
from serialization import jsonpickle
from hashlib import sha256

from credential_aliases import *

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element as G1EP, G2Element as G2EP


######################
## Helper Functions ##
######################

def bn_list_to_bytes_list(attributes: List[Bn]) -> List[bytes]:
  """Convert a list of attributes (bn type object) to a list of bytes"""
  return [jsonpickle.encode(bn) for bn in attributes]


def check_attribute_map(pk: PublicKey,
                        attributes: AttributeMap) -> bool:
  """check """

  if len(attributes) > len(pk): #len(pk) = len(list_of_Y)
    return False

  return all([attr > 0 and attr in pk.attributes for attr in attributes.values()])



def non_interactive_zkp(pk: PublicKey, 
                        t: Bn,
                        user_attributes: AttributeMap,
                        user_commitment: G1EP) -> PedersenKnowledgeProof:
  """Implementation of non-interactive zero-knowledge proof"""
  # recompute user_commitment using pk, t, and user_attributes
  
  U = len(user_attributes)
  user_attributes = dict(sorted(user_attributes.items()))

  list_of_r = [G1.order().random() for _ in range(U + 1)] if U > 0 else [G1.order().random()]
  list_of_rth_power_of_Y = [pk.list_of_Y[idx - 1] ** list_of_r[i + 1] for i, idx in enumerate(user_attributes.keys())]
  R = (pk.g ** list_of_r[0]) * G1.prod(list_of_rth_power_of_Y)

  # get challenge
  challenge = Bn.from_hex(
        sha256(jsonpickle.encode((pk.get_pk(), R, user_commitment)).encode()).hexdigest()
    ).mod(G1.order())

  r_0 = (list_of_r[0] - challenge * t).mod(G1.order())
  list_of_s_sub_x =  [(r - challenge * attr).mod(G1.order()) for r, attr in zip(list_of_r[1:], user_attributes.values())]
  list_of_r_bind_idx = list(zip(user_attributes, list_of_s_sub_x)) if U > 0 else []
  
  #bind each user_attribute with its corresponding s
  return PedersenKnowledgeProof(challenge.mod(G1.order()), [r_0] + list_of_r_bind_idx)


  
def created_issue_request_knowledge_proof(request: IssueRequest,
                                         pk: PublicKey) -> bool:
    """Verifies the Zero Knowledge Proof object that shows knowledge of commit value t and attributes (a_i) for i in U, the user attributes hidden to issuer. Follows the Pederson commitment implementation from Exercice Set 1.2 with a non-interactive adaptation"""
    
    com, pi = request.user_commitment, request.pi
    n = len(pi.get_list_of_r())

    R_prime = (com ** pi.challenge) * (pk.g ** pi.get_r())
    R_prime *= G1.prod([pk.list_of_Y[i - 1] ** a for i, a in pi.get_list_of_r()]) if n > 0 else 1
    
    challenge_prime = Bn.from_hex(
        sha256(jsonpickle.encode((pk.get_pk(), R_prime, com)).encode()).hexdigest()
    ).mod(G1.order())

    return pi.challenge == challenge_prime

  













  