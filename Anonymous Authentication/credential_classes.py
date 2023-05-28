"""Store all the classes of signature schema"""

from typing import Any, List, Dict, Tuple

import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element as G1EP, G2Element as G2EP


# SecretKey = Any
# PublicKey = Any
# Signature = Any
Attribute = Bn
AttributeMap = dict[int, Attribute] #dict[i, attribute_i]
# dict[G1EP, dict[int, Attribute]] # dict[t, dict[i, attribute_i]]
# IssueRequest = Any
# BlindSignature = Any
# AnonymousCredential = Any
# DisclosureProof = Any


class PublicKey:
  """Create a PublicKey object"""
# PublicKey(x, g, g_hat, list_of_y, attributes)
  def __init__(self, x: G1EP,
                     g: G1EP,
                     g_hat: G2EP,
                     list_of_y: List[G1EP],
                     attributes: List[Attribute]) -> None:

    self.x = x.mod(G1.order())# x should in G1.order()
    self.g = g
    self.g_hat= g_hat
    self.X_hat = g_hat ** self.x
    self.list_of_y = [y.mod(G1.order()) for y in list_of_y]
    # self.list_of_y = list_of_y
    self.list_of_Y = [g ** y for y in self.list_of_y]
    self.list_of_Y_hat = [g_hat ** y for y in self.list_of_y]
    # self.pk = [self.g] + self.list_of_Y + [self.g_hat, self.X_hat] + self.list_of_Y_hat
    self.attributes = attributes

  def __len__(self) -> int:
    return len(self.list_of_Y)

  def get_pk(self) -> List:
    return [self.g] + self.list_of_Y + [self.g_hat, self.X_hat] + self.list_of_Y_hat
    


class SecretKey:
  """Create a SecretKey object"""
# SecretKey(x, g, list_of_y)
  def __init__(self, x: G1EP,
                     g: G1EP,
                     list_of_y: List[G1EP],
                     attributes: List[Attribute]) -> None:

    self.x = x.mod(G1.order())
    self.g = g
    self.X = g ** x
    self.list_of_y = [y.mod(G1.order()) for y in list_of_y]
    # self.sk = [self.x, self.X] + self.list_of_y
    self.attributes = attributes

  def __len__(self) -> int:
    return len(self.list_of_y)

  def get_sk(self) -> List:
    return [self.x, self.X] + self.list_of_y
     


class Signature:
  """Create a Signature object"""
# sigma = (sigma1, sigma2) 
  def __init__(self, sigma1: G1EP,
                     sigma2: G1EP) -> None:

    self.sigma1 = sigma1
    self.sigma2 = sigma2

  def get_signature(self):
    return (self.sigma1, self.sigma2)



class BlindSignature:
  """Create a Unblinding Signature object"""
# (sigma_prime_sub1, sigma_prime_sub2, issuer_attributes)
  def __init__(self, sigma_prime_sub1: G1EP,
                     sigma_prime_sub2: G1EP,
                     issuer_attributes: AttributeMap) -> None:

    self.sigma_prime_sub1 = sigma_prime_sub1
    self.sigma_prime_sub2 = sigma_prime_sub2
    self.issuer_attributes = issuer_attributes

  def get_sigmas(self):
    return (self.sigma_prime_sub1, self.sigma_prime_sub2)


class AnonymousCredential:
  """Create an anonymous credential for user"""
# 
  def __init__(self, signature: tuple, attributes: AttributeMap) -> None:
    self.signature = signature
    self.attributes = attributes

  def get_credential(self):
    return (self.signature, self.attributes)


class PedersenKnowledgeProof:
    """
    Make all the received attributes modulo G1 order to be positive
    """
    # PedersenKnowledgeProof(challenge, [a random number] + zip[int, s])
    def __init__(self,
                 challenge: Bn,
                 list_of_r_bind_attrs_idx: List) -> None:

      self.challenge = challenge
      self.r = list_of_r_bind_attrs_idx[0]
      self.list_of_r_bind_attrs = list_of_r_bind_attrs_idx[1:]

    def get_list_of_r(self):
      return self.list_of_r_bind_attrs

    def get_r(self):
      return self.r


class IssueRequest:
  """create a issue request"""
  # IssueRequest(user_commitment, pi)
  def __init__(self,
                user_commitment: G1EP,
                pi: PedersenKnowledgeProof) -> None:

    self.user_commitment = user_commitment
    self.pi = pi


class DisclosureProof:
    """
    Store the randomized final signature, the disclosed attributes and the proof.
    """
    def __init__(self, signature: Signature,
                       pi: PedersenKnowledgeProof,
                       disclosure_attributes: AttributeMap) -> None:
        
      self.signature = signature
      self.pi = pi
      self.disclosure_attributes = disclosure_attributes

    def get_signature(self):
      return self.signature

    def get_proof(self):
      return self.pi

    def get_disclosure_attributes(self):
      return self.disclosure_attributes


