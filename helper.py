from typing import Any, List, Tuple
from serialization import jsonpickle
from hashlib import sha256

from credential_classes import *

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
 
    return all([(i > 0 and i <= len(pk) and attr >= 0) and 
              (attr in pk.attributes if i > 1 else True) 
              for i, attr in attributes.items()])



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

  
##############################
####functions for stroll.py###
##############################

def generate_hidden_attrs(pk: PublicKey, revealed_attributes: List[Bn], credential: AnonymousCredential):
  """Generate hidden attributes"""
  
  disclosed_attributes = generate_disclosed_attributes(pk, revealed_attributes).items()
  
  return {
     i: attr for i, attr in credential.attributes.items() if (i, attr) not in disclosed_attributes
  }


def string_to_bn(str_attribute: str) -> Bn:
    """transform one subscription from the string type to Bn type"""
    
    return Bn.from_binary(sha256(str_attribute.encode()).digest()).mod(G1.order())



def list_of_string_to_bn(list_of_string: List[str]) -> List[Bn]:
    """transform a list of subscriptions from the string type to Bn type"""

    return list(map(lambda s: string_to_bn(s), list_of_string))


def check_subscriptions(pk: PublicKey, subscriptions: List[str]) -> bool:
    """Check if all subscriptions are in a given list of subscriptions"""

    subscripted_attributes = list_of_string_to_bn(subscriptions)

    return len(subscriptions) > 0 and all([attr in pk.attributes for attr in subscripted_attributes])

def build_attribute_map_for_all_attributes(attributes: List[Bn]) -> AttributeMap:
    """transform all attributes from List[Bn] to AttributeMap type"""

    return dict([(i + 1, attr) for i, attr in list(enumerate(attributes))[1:]])


def generate_issuer_attributes(pk: PublicKey, subscriptions: List[str]) -> AttributeMap:
    """generate the AttributeMap for issuer attributes"""
    # transform all attributes from List[Bn] to AttributeMap, key's range [2, L]
    # 
    subscriptions_dict = {i + 1: attr for i, attr in list(enumerate(pk.attributes))[1:]}
    subscripted_attributes = list_of_string_to_bn(subscriptions)

    return {i: attr if attr in subscripted_attributes else string_to_bn("None") 
                                            for i, attr in subscriptions_dict.items()}


def generate_disclosed_attributes(pk: PublicKey, revealed_attributes: List[Bn]) -> AttributeMap:
    """generate the AttributeMap for disclosed attributes"""
    # transform all attributes from List[Bn] to AttributeMap, key's range [2, L]
    all_attributes = build_attribute_map_for_all_attributes(pk.attributes)
    disclosed_attributes = dict()
    for index, attribute in all_attributes.items():
        if attribute in revealed_attributes:
            disclosed_attributes[index] = attribute

    return disclosed_attributes

  