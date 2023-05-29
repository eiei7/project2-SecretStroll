"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple
from serialization import jsonpickle

from credential_classes import *
from helper import *

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element as G1EP, G2Element as G2EP


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    n = len(attributes)

    if n < 1:
      raise ValueError("Attributes should be greater than 1")

    for attr in attributes:
      if not isinstance(attr, Bn) or attr < 0:
        raise TypeError("All attributes should be Bn positive objects")

    g = G1.generator()
    g_hat = G2.generator()
    x = G1.order().random()
    # same length as n(L)
    list_of_y = [G1.order().random() for _ in range(n)]

    pk = PublicKey(x, g, g_hat, list_of_y, attributes)
    sk = SecretKey(x, g, list_of_y, attributes)

    return sk, pk
    

def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    n = len(msgs)
    if n != len(sk):
      raise ValueError("Length of messages should equal to length of secret key")

    for msg in msgs:
      if not isinstance(jsonpickle.decode(msg), Bn):
        raise TypeError("All messages should be jsonpickle encoded Bn objects")
    
    h = G1.generator()
    msgs = [jsonpickle.decode(msg) for msg in msgs]
    sum_prod_of_ym = sum([sk.list_of_y[i] * msgs[i] for i, msg in enumerate(msgs)])
    h_p = h ** (sk.x + sum_prod_of_ym)

    return Signature(h, h_p)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    n = len(msgs)
    if n != len(pk):
      raise ValueError("Length of messages should equal to length of public key")

    for msg in msgs:
      if not isinstance(jsonpickle.decode(msg), Bn):
        raise TypeError("All messages should be jsonpickle encoded Bn objects")
    
    (sigma1, sigma2) = signature.get_signature()
    # check that σ1 is not the unity element in G1
    if sigma1 == G1.unity():
       return False
      
    list_of_mth_power_of_Y_hat = [Y ** jsonpickle.decode(m) for (Y, m) in zip(pk.list_of_Y_hat, msgs)]
    prod_of_X_hat_and_lmpYh = pk.X_hat * G2.prod(list_of_mth_power_of_Y_hat)

    print("left_side: ", sigma1.pair(prod_of_X_hat_and_lmpYh))
    print("right_side: ", sigma2.pair(pk.g_hat)) 

    return sigma1.pair(prod_of_X_hat_and_lmpYh) == sigma2.pair(pk.g_hat)
    


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest, Tuple[Bn, AttributeMap]]:
    """ Create an issuance request
    dict[t, dict[int, attr]]
    This corresponds to the "user commitment" step in the issuance protocol.
    return IssueRequest and t
    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    if not check_attribute_map(pk, user_attributes):
      raise ValueError("Too much attributes or there are non-positive attribute in attributes list")

    t = G1.order().random()

    # pk.list_of_Y's index range[0, L-1], the user_attributes() key's range [1, L]
    list_of_ath_power_of_Y = [pk.list_of_Y[i - 1] ** a for i, a in user_attributes.items()]
    user_commitment = (pk.g ** t) * G1.prod(list_of_ath_power_of_Y)

    pi = non_interactive_zkp(pk, t, user_attributes, user_commitment)

    return IssueRequest(user_commitment, pi), (t, user_attributes)
    

def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    if not check_attribute_map(pk, issuer_attributes):
      raise ValueError("Too much attributes or there are non-positive attribute in attributes list")

    # issuer verify the proof before signing
    if not created_issue_request_knowledge_proof(request, pk):
        raise ValueError("Incorrect proof of knowledge associated with a created issue request")

    u = G1.order().random()
    sigma_prime_sub1 = pk.g ** u
    list_of_ath_power_of_Y = [pk.list_of_Y[i - 1] ** a for i, a in issuer_attributes.items()]
    prod_of_X_C_lapY = sk.X * request.user_commitment * G1.prod(list_of_ath_power_of_Y)
    sigma_prime_sub2 = prod_of_X_C_lapY ** u

    return BlindSignature(sigma_prime_sub1, sigma_prime_sub2, issuer_attributes)


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        state: Tuple[Bn, AttributeMap]
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    t, user_attributes = state

    if not check_attribute_map(pk, response.issuer_attributes
                               ) or not check_attribute_map(pk,
                               user_attributes):
      raise ValueError("Too much attributes or there are non-positive attribute in attributes list")

    if len(user_attributes) + len(response.issuer_attributes) != len(pk):
      raise ValueError("Length of messages should equal to length of public key")

    # final signature
    signature = Signature(response.sigma_prime_sub1,
                          response.sigma_prime_sub2 / (response.sigma_prime_sub1 ** t))
    
    # attributes = user_attributes | response.issuer_attributes
    attributes = dict(
        sorted((user_attributes | response.issuer_attributes).items())
    )

    # check if the signature on the attributes is valid
    if not verify(pk, signature, bn_list_to_bytes_list(list(attributes.values()))):
        raise ValueError(
            "The provided signature is not valid for all the given attributes"
        )
    return AnonymousCredential(signature, attributes)
    


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: AttributeMap,
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """

    hidden_attributes = dict(sorted(hidden_attributes.items()))

    if not check_attribute_map(pk, credential.attributes
                               ) or not check_attribute_map(pk,
                               hidden_attributes):
      raise ValueError("Too much attributes or there are non-positive attribute in attributes list")

    r = GT.order().random()
    t = GT.order().random()
    # randomized signature
    sigma_sub1, sigma_sub2 = credential.signature.get_signature()
    signature = Signature(sigma_sub1 ** r, (sigma_sub2 * (sigma_sub1 ** t)) ** r)
    sigma_prime_sub1, sigma_prime_sub2 = signature.get_signature()

    # right side: com
    list_of_ath_power_of_Y_hat = [sigma_prime_sub1.pair(pk.list_of_Y_hat[idx - 1]) ** a for idx, a in hidden_attributes.items()]
    com = sigma_prime_sub1.pair(pk.g_hat) ** t * GT.prod(list_of_ath_power_of_Y_hat)

    # left side: R (generate proof)
    H = len(hidden_attributes)
    # list_of_r[0] := x is a random num like t
    list_of_r = [GT.order().random() for _ in range(H + 1)] if H > 0 else [GT.order().random()]
    list_of_rth_power_of_Y_hat = [sigma_prime_sub1.pair(pk.list_of_Y_hat[idx - 1]) ** list_of_r[i + 1] for i, (idx, _) in enumerate(hidden_attributes.items())]
    R = (sigma_prime_sub1.pair(pk.g_hat) ** list_of_r[0]) * GT.prod(list_of_rth_power_of_Y_hat)

    # get challenge
    challenge = Bn.from_hex(
          sha256(jsonpickle.encode((pk.get_pk(), com, R, message)).encode()).hexdigest()
      ).mod(GT.order())

    r_0 = (list_of_r[0] - challenge * t).mod(GT.order())
    list_of_s_sub_r =  [(r - challenge * attr).mod(GT.order()) for r, attr in zip(list_of_r[1:], hidden_attributes.values())]
    list_of_s_sub_r_bind_idx = list(zip(hidden_attributes.keys(), list_of_s_sub_r)) if H > 0 else []

    # input = (challenge, [r - challenge * t'] + [(idx, s_sub_r) for i in list_of_r])
    pi = PedersenKnowledgeProof(challenge.mod(GT.order()), [r_0] + list_of_s_sub_r_bind_idx)


    return DisclosureProof(signature, pi)
    


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        disclosed_attributes: AttributeMap,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    
    # disclosure_attributes = disclosure_proof.get_disclosure_attributes()
    D = len(disclosed_attributes)
    disclosed_attributes = dict(sorted(disclosed_attributes.items()))

    if not check_attribute_map(pk, disclosed_attributes):
      raise ValueError("Too much attributes or there are non-positive attribute in attributes list")

    (sigma_prime_sub1, sigma_prime_sub2) = disclosure_proof.signature.get_signature()
    if sigma_prime_sub1 == G1.unity():
       return False

    # left side: com, note that -a_i in the set of disclosure attributes
    list_of_neg_ath_power_of_Y_hat = [sigma_prime_sub1.pair(pk.list_of_Y_hat[idx - 1]) ** (-a) 
                                          for idx, a in disclosed_attributes.items()] if D > 0 else []
    com = ((sigma_prime_sub2.pair(pk.g_hat)) * GT.prod(list_of_neg_ath_power_of_Y_hat)) / (sigma_prime_sub1.pair(pk.X_hat))

    # recompute the commitment
    # get com^c
    com_to_the_c = com ** disclosure_proof.pi.challenge
    # get t' (:= r)
    t_prime = disclosure_proof.pi.get_r()
    R_prime = com_to_the_c * (sigma_prime_sub1.pair(pk.g_hat) ** t_prime)

    # if there exist hidden attributes
    if len(pk) > D:
      # get the list of response for hidden attributes
      list_of_r = disclosure_proof.pi.get_list_of_r()
      list_of_ath_power_of_Y_hat = [sigma_prime_sub1.pair(pk.list_of_Y_hat[idx - 1]) ** a for idx, a in list_of_r]
      R_prime *= GT.prod(list_of_ath_power_of_Y_hat)

    # get challenge'
    challenge_prime = Bn.from_hex(
          sha256(jsonpickle.encode((pk.get_pk(), com, R_prime, message)).encode()).hexdigest()
      ).mod(GT.order())

    print(disclosure_proof.pi.challenge)
    print(challenge_prime)

    # verify C == C'
    return disclosure_proof.pi.challenge == challenge_prime
    
