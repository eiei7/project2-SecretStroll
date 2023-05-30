from hashlib import sha256

from credential_classes import *

def string_to_bn(str_attribute: str) -> Bn:
    """transform one subscription from the string type to Bn type"""
    attribute = Bn.from_binary(sha256(str_attribute.encode()).digest()).mode(G1.order())
    return attribute


def list_of_string_to_bn(list_of_string: List[str]) -> List[Bn]:
    """transform a list of subscriptions from the string type to Bn type"""
    return list(map(lambda s: string_to_bn(s), list_of_string))


def check_subscription_valid(pk: PublicKey, attributes: List[Attribute]) -> bool:
    """check if the subscription(attribute) provided is unknown"""
    if not len(attributes) > 0:
        return False
    for attribute in attributes:
        if attribute not in pk.attributes:
            return False
    return True


def build_attribute_map_for_all_attributes(attributes: List[Bn]) -> AttributeMap:
    """transform all attributes from List[Bn] to AttributeMap type"""
    attribute_map = {}
    for idx, attribute in enumerate(attributes, start=1):
        attribute_map[idx + 1] = attribute
    return attribute_map


def generate_issuer_attributes(pk: PublicKey, requested_attributes: List[Bn], username: str) -> AttributeMap:
    """generate the AttributeMap for issuer attributes"""
    # transform all attributes from List[Bn] to AttributeMap, key's range [2, L]
    all_attributes = build_attribute_map_for_all_attributes(pk.attributes)
    issuer_attributes = dict()
    issuer_attributes[1] = string_to_bn(username)
    for index, attribute in all_attributes.items():
        if attribute in requested_attributes:
            issuer_attributes[index] = attribute
        else:
            issuer_attributes[index] = string_to_bn('None')

    return issuer_attributes


def generate_disclosed_attributes(pk: PublicKey, revealed_attributes: List[Bn]) -> AttributeMap:
    """generate the AttributeMap for disclosed attributes"""
    # transform all attributes from List[Bn] to AttributeMap, key's range [2, L]
    all_attributes = build_attribute_map_for_all_attributes(pk.attributes)
    disclosed_attributes = dict()
    for index, attribute in all_attributes.items():
        if attribute in revealed_attributes:
            disclosed_attributes[index] = attribute

    return disclosed_attributes