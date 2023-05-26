from typing import List, Dict, Tuple

import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1Element, G2Element, G1, GT


class SecretKey:
    def __init__(self, x, X, y):
        self.x = x
        self.X = X
        self.y = y
        self.sk = [self.x, self.X] + self.y
        self.L = len(self.y)


class PublicKey:
    def __init__(self, g, Y, gt, Xt, Yt, all_attributes):
        self.g = g
        self.Y = Y
        self.gt = gt
        self.Xt = Xt
        self.Yt = Yt
        # concatenate all elements into a list
        self.pk = [self.g] + self.Y + [self.gt, self.Xt] + self.Yt
        self.L = len(self.Y)
        self.all_attributes = all_attributes

    def check_attribute_map(self, attributes: Dict[int, Bn]) -> bool:
        """
        Check if the length of attributes and all (index,attribute) pairs are valid
        """
        if len(attributes) > self.L:
            return False
        for index, attribute in attributes.items():
            if not self.check_index_attribute_valid(index, attribute):
                return False
        return True

    def check_index_attribute_valid(self, index: int, attribute: Bn) -> bool:
        """
        Checks if the index, the attribute, the subscription is valid
        Checks if the attribute is a valid subscription by verifying if it exists in the pk.all_attributes list.
        Note that the user secret attribute is represented as `None` in the list `pk.all_attributes`.
        """
        # check index range [1, L]
        is_valid_index = 1 <= index <= self.L
        # check attribute range >= 0
        is_positive_attribute = attribute >= 0
        # check if the attribute is in pk.all_attributes list
        if index > 1:
            is_valid_subscription = attribute in self.all_attributes
        else:
            is_valid_subscription = True

        return is_valid_index and is_positive_attribute and is_valid_subscription

    @staticmethod
    def attributes_to_bytes(all_attributes: Dict[int, Bn]) -> List[bytes]:
        """
        Converts an attribute map to a list of encoded values (bytes) that are sorted by their keys in attribute map
        """
        sorted_all_attributes = dict(sorted(all_attributes.items()))
        return list(map(lambda value: jsonpickle.encode(value), sorted_all_attributes.values()))


class State:
    """arguments needed to pass to the `obtain_credential` function."""
    def __init__(self,
                 t: Bn,
                 user_attribute_map: Dict[int, Bn] = None,
                 issuer_attribute_map: Dict[int, Bn] = None):
        self.t = t
        self.user_attribute_map = user_attribute_map
        self.issuer_attribute_map = issuer_attribute_map


class Signature:
    def __init__(self, sigma1, sigma2):
        self.sigma1 = sigma1
        self.sigma2 = sigma2
        self.sigma = (sigma1, sigma2)

class BlindSignature(Signature):
    def __init__(self,
                 sigma1: G1Element,
                 sigma2: G1Element,
                 state: State):
        super().__init__(sigma1, sigma2)
        self.state = state
        self.sigma = (sigma1, sigma2)


class PedersenProofResponse:
    """
    Make all the received attributes modulo G1 order to be positive
    """
    def __init__(self,
                 challenge: Bn,
                 response_index_zero: Bn,
                 response_bind_index: List[Tuple[Bn, int]]):
        self.challenge = challenge.mod(G1.order())
        self.response_index_zero = response_index_zero.mod(G1.order())
        self.response_bind_index = list(map(lambda a: (a[0].mod(G1.order()), a[1]), response_bind_index))



class IssueRequest:
    def __init__(self,
                 user_commitment: G1Element,
                 proof_response: PedersenProofResponse,
                 state: State):
        self.user_commitment = user_commitment
        self.proof_response = proof_response
        self.state = state


class AnonymousCredential:
    """
    Store the final signature and all the attributes it signs for.
    """
    def __init__(self,
                 sigma: Signature,
                 all_attributes: Dict[int, Bn]):
        self.sigma = sigma
        # the attribute values are transformed to their equivalent values within the valid range
        self.all_attributes = dict(map(lambda pair: (pair[0], pair[1].mod(G1.order())), all_attributes.items()))


class DisclosureProof:
    """
    Store the randomized final signature, the disclosed attributes and the proof.
    """
    def __init__(self,
                 randomized_signature: Signature,
                 # disclosed_attributes: Dict[int, Bn],
                 proof_response: PedersenProofResponse):
        self.randomized_signature = randomized_signature
        # self.disclosed_attributes = disclosed_attributes
        self.proof_response = proof_response


