import hashlib
from functools import reduce
from hashlib import sha256
from typing import List, Tuple, Dict

import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1Element, G1, GT

# from credential import AttributeMap
from credential_entity import PublicKey, IssueRequest, Signature, DisclosureProof, PedersenProofResponse


# def calculate_challenge(pk: PublicKey, pedersen_commitment: G1Element, user_commitment: G1Element, msg = None):
#     agg = str(pedersen_commitment.to_binary()) + str(user_commitment.to_binary()) + str(msg)
#     for val in pk.pk:
#         agg += str(val)
#     return Bn.from_binary(hashlib.sha256(agg.encode()).digest())


class Proof:
    def __init__(self,
                 pk: PublicKey,
                 t: Bn = None,
                 attributes: Dict[int, Bn] = None,
                 user_commitment: G1Element = None,
                 message: bytes = None,
                 is_issuance: bool = True,
                 randomized_signature: Signature = None):
        self.pk = pk
        self.t = t
        self.attributes = attributes
        self.user_commitment = user_commitment
        self.message = message
        self.is_issuance = is_issuance
        self.randomized_signature = randomized_signature

    def signature(self) -> PedersenProofResponse:
        """
        Useful when the user do a (non-interactive) zero-knowledge proof in both the issuance protocol and the showing protocol.
        Compute the pedersen commitment, challenge and response
        """
        # get the length |U|
        length = len(self.attributes)
        # sort the attributes in increasing order
        sorted_attributes = dict(sorted(self.attributes.items()))

        # compute the pedersen commitment
        # case1: Issuance Protocol
        if self.is_issuance:
            # random_values length |U| + 1
            random_values = [G1.order().random() for _ in range(length + 1)]

            pedersen_commitment = self.pk.g ** random_values[0]
            # index range [1, L], i range [0, |U|)
            # pk.Y[index] range [0, L-1]
            # random_values range [1, |U|], random_values[0] has already been used
            pedersen_commitment *= reduce(lambda a, b: a * b,
                                          (self.pk.Y[index - 1] ** random_values[i + 1]
                                           for i, index in enumerate(sorted_attributes.keys())))

            # compute the challenge using pedersen commitment
            # challenge = calculate_challenge(self.pk.pk, pedersen_commitment, self.user_commitment)
            challenge = Bn.from_hex(sha256(jsonpickle.encode((self.pk.pk, pedersen_commitment, self.user_commitment)).encode()).hexdigest()).mod(G1.order())


        # case2: Showing Protocol
        else:
            # random_values length |U| + 1
            random_values = [GT.order().random() for _ in range(length + 1)]

            pedersen_commitment = self.randomized_signature.sigma1.pair(self.pk.gt) ** random_values[0]
            # index range [1, L], i range [0, |H|)
            # pk.Y[index] range [0, L-1]
            # random_values range [1, |H|], random_values[0] has already been used
            # pedersen_commitment *= reduce(lambda a, b: a * b,
            #                               (self.randomized_signature.sigma1.pair(
            #                                   self.pk.Yt[index - 1] ** random_values[i + 1])
            #                                for i, index in enumerate(sorted_attributes.keys())))
            for i, index in enumerate(sorted_attributes.keys()):
                pedersen_commitment *= (self.randomized_signature.sigma1.pair(self.pk.Yt[index - 1] ** random_values[i + 1]))

            # compute the challenge using pedersen commitment
            challenge = Bn.from_hex(sha256(jsonpickle.encode(
                (self.pk.pk, self.user_commitment, pedersen_commitment, self.message)).encode()).hexdigest()).mod(
                GT.order())

        # compute the response
        # secrets length |U| + 1, secrets[0] = t
        secrets = [self.t] + list(sorted_attributes.values())
        response = [random_value - challenge * secret for random_value, secret in zip(random_values, secrets)]
        # generate pair(response, index), where index represents the attribute
        response_bind_index = list(zip(response[1:], sorted_attributes.keys()))

        return PedersenProofResponse(challenge, response[0], response_bind_index)

    def issuer_verify(self, request: IssueRequest) -> bool:
        """
        Verifies the validity of proof π with respect to commitment
        The user attributes are hidden to issuer.
        """
        user_commitment, proof_response = request.user_commitment, request.proof_response
        # recompute the commitment based on commitment and response received
        verify_commitment = user_commitment ** proof_response.challenge * self.pk.g ** proof_response.response_index_zero
        verify_commitment *= reduce(lambda a, b: a * b,
                                    (self.pk.Y[pair[1] - 1] ** pair[0] for pair in proof_response.response_bind_index))

        # recompute the challenge
        # verify_challenge = calculate_challenge(self.pk.pk, verify_commitment, user_commitment)
        verify_challenge = Bn.from_hex(sha256(jsonpickle.encode(
            (self.pk.pk, verify_commitment, user_commitment)).encode()).hexdigest()).mod(G1.order())

        # compare recomputed challenge with the challenge received
        return verify_challenge == proof_response.challenge

    def verifier_verify(self, commitment: G1Element, disclosure_proof: DisclosureProof, message: bytes) -> bool:
        """
        Checks that the user has a valid signature under public key pk over
        the disclosed attributes (a_i)i∈D by verifying the proof π.
        """
        signature = disclosure_proof.randomized_signature
        t = disclosure_proof.proof_response.response_index_zero
        # recompute the commitment based on commitment and response received
        verify_commitment = (commitment ** disclosure_proof.proof_response.challenge) * (signature.sigma1.pair(self.pk.gt) ** t)
        verify_commitment *= reduce(lambda a, b: a * b,
                                    (signature.sigma1.pair(self.pk.Yt[index - 1]) ** response
                                     for (response, index) in disclosure_proof.proof_response.response_bind_index))

        # recompute the challenge
        verify_challenge = Bn.from_hex(sha256(jsonpickle.encode(
            (self.pk.pk, commitment, verify_commitment, message)).encode()).hexdigest()).mod(GT.order())

        # compare recomputed challenge with the challenge received
        return verify_challenge == disclosure_proof.proof_response.challenge
