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
from functools import reduce
from typing import Any, List, Tuple, Dict

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT

from Proof import Proof
from credential_entity import PublicKey, SecretKey, Signature, State, IssueRequest, BlindSignature, AnonymousCredential, \
    DisclosureProof
from serialization import jsonpickle


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = Any
# PublicKey = Any
# Signature = Any
Attribute = Bn
AttributeMap = Dict[int, Bn]
# IssueRequest = Any
# BlindSignature = Any
# AnonymousCredential = Any
# DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    l = len(attributes)
    if l < 1:
        raise ValueError("There must be at least one attribute")
    for attr in attributes:
        if not isinstance(attr, Bn) or not attr >= 0:
            raise TypeError("Attributes should be Bn positive objects")
    x = G1.order().random().mod(G1.order())
    y = [G1.order().random().mod(G1.order()) for i in range(l)]
    # random generator
    g = G1.generator() ** G1.order().random()
    gt = G2.generator() ** G2.order().random()
    X = g ** x
    Xt = gt ** x
    Y = [g ** i for i in y]
    Yt = [gt ** i for i in y]

    return SecretKey(x, X, y), PublicKey(g, Y, gt, Xt, Yt, attributes)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    if sk.L != len(msgs):
        raise ValueError("Messages' length should be L")
    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be jsonpickle encoded Bn objects")
    h = G1.generator() ** G1.order().random()
    hx = h ** sk.x
    ym = 0
    for i, v in enumerate(sk.y):
        ym += v * jsonpickle.decode(msgs[i])
    hx *= h ** ym
    return Signature(h, hx)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    if pk.L != len(msgs):
        raise ValueError("Messages should have length L")

    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be jsonpickle encoded Bn objects")

    # check if σ1 is the unity element in G1
    if signature.sigma1 == G1.unity():
        return False
    # second element in the left pair
    l2 = pk.Xt
    for i, msg in enumerate(msgs):
        l2 *= pk.Yt[i] ** jsonpickle.decode(msg)
    return signature.sigma1.pair(l2) == signature.sigma2.pair(pk.gt)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    if not pk.check_attribute_map(user_attributes):
        raise ValueError('Invalid User_attributes Input')

    # generate random t
    t = G1.order().random()

    # compute the user commitment C
    user_commitment = pk.g ** t
    # pk.Y[i] - i's range is in [0, L-1]
    # user_attributes - index's range is in [1, L]
    for index, attribute in user_attributes.items():
        user_commitment *= pk.Y[index - 1] ** attribute

    # compute the non-interactive zero-knowledge proof π
    proof_response = Proof(pk = pk, t = t, attributes = user_attributes, user_commitment = user_commitment).signature()

    return IssueRequest(user_commitment, proof_response, State(t, user_attribute_map=user_attributes))

def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    if not pk.check_attribute_map(issuer_attributes):
        raise ValueError('Invalid Issuer_attributes Input')

    # verifies the validity of proof π with respect to commitment
    if not Proof(pk = pk).issuer_verify(request):
        raise ValueError('Incorrect proof of knowledge associated with the issue request')

    # signing process
    # generate the random num u
    u = G1.order().random()
    sigma1 = pk.g ** u
    sigma2 = sk.X * request.user_commitment
    # index range [1, L], Y[i] i's range [0, L-1]
    sigma2 *= reduce(lambda a, b: a * b, (pk.Y[index - 1] ** attribute for index, attribute in issuer_attributes.items()))

    # add issuer_attributes to state
    request.state.issuer_attribute_map = issuer_attributes

    return BlindSignature(sigma1, sigma2 ** u, request.state)


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    if not pk.check_attribute_map(response.state.issuer_attribute_map) or \
            not pk.check_attribute_map(response.state.user_attribute_map):
        raise ValueError('Incorrect attributes map')

    sigma1 = response.sigma1
    sigma2 = response.sigma2 / (sigma1 ** response.state.t)
    sigma = Signature(sigma1, sigma2)

    # union user_attributes and issuer_attributes
    all_attributes = response.state.user_attribute_map.copy()
    all_attributes.update(response.state.issuer_attribute_map.copy())
    # sort the dict to have the attributes aligned with their index
    sorted_all_attributes = dict(sorted(all_attributes.items()))

    # call verify func() to verify that a signature over a message vector (m1,...,mL) is valid
    msgs = pk.attributes_to_bytes(all_attributes)
    if not verify(pk, sigma, msgs):
        raise ValueError('The signature is not a valid PS signature on the attributes a1 , . . . , aL')

    return AnonymousCredential(sigma, sorted_all_attributes)


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: AttributeMap,
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    if not pk.check_attribute_map(hidden_attributes) or not pk.check_attribute_map(credential.all_attributes):
        raise ValueError('Incorrect attributes map')

    sorted_hidden_attributes = dict(sorted(hidden_attributes.items()))

    # pick random values r, t
    r = GT.order().random()
    t = GT.order().random()

    # compute the randomized signature
    randomized_sigma1 = credential.sigma.sigma1 ** r
    randomized_sigma2 = (credential.sigma.sigma2 * credential.sigma.sigma1 ** t) ** r
    randomized_signature = Signature(randomized_sigma1, randomized_sigma2)

    # user compute the commitment C of hidden attributes
    hidden_commitment = randomized_sigma1.pair(pk.gt) ** t
    # pk.Y[i] - i's range is in [0, L-1]
    # hidden_attributes - index's range is in [1, L]
    for index, attribute in sorted_hidden_attributes.items():
        hidden_commitment *= randomized_sigma1.pair(pk.Yt[index-1] ** attribute)

    # compute the non-interactive zero-knowledge proof π
    proof_response = Proof(pk = pk, t = t, attributes = sorted_hidden_attributes, user_commitment = hidden_commitment, message = message,
                           is_issuance=False, randomized_signature=randomized_signature).signature()

    # generate the disclosed attributes
    hidden_attributes_index = list(hidden_attributes.keys())
    disclosed_attributes = dict()
    for index, attribute in credential.all_attributes.items():
        if index not in hidden_attributes_index:
            disclosed_attributes[index] = attribute

    return DisclosureProof(randomized_signature, disclosed_attributes, proof_response)


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    if not pk.check_attribute_map(disclosure_proof.disclosed_attributes):
        raise ValueError('Invalid Issuer_attributes Input')

    # verify that sigma1 is not the unity element in G1
    if disclosure_proof.randomized_signature.sigma1 == G1.unity:
        return False

    sorted_disclosed_attributes = dict(sorted(disclosure_proof.disclosed_attributes.items()))
    signature = disclosure_proof.randomized_signature

    # compute the left side of proof
    commitment = signature.sigma2.pair(pk.gt)
    for index, attribute in sorted_disclosed_attributes.items():
        commitment *= signature.sigma1.pair(pk.Yt[index - 1] ** -attribute)
    commitment /= signature.sigma1.pair(pk.Xt)

    # verifies the validity of proof π with respect to commitment
    return Proof(pk = pk).verifier_verify(commitment, disclosure_proof, message)
