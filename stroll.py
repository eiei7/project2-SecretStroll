"""
Classes that you need to complete.
"""

from typing import List, Tuple

# Optional import
from serialization import *
from helper import *
from credential import *

from petrelic.multiplicative.pairing import G1

# Type aliases
State = Ustate


class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        attributes = list_of_string_to_bn(["None"] + sorted(subscriptions))
        sk, pk = generate_key(attributes)
        # encode sk, pk to bytes
        server_sk = jsonpickle.encode(sk).encode()
        server_pk = jsonpickle.encode(pk).encode()

        return server_sk, server_pk


    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk = jsonpickle.decode(server_sk)
        pk = jsonpickle.decode(server_pk)
        issue_request = jsonpickle.decode(issuance_request)

        # check the type of parameter
        if not isinstance(sk, SecretKey):
          raise TypeError("Not a valid ScretKey Object")
            
        if not isinstance(pk, PublicKey):
          raise TypeError("Not a valid PublicKey Object")
        
        if not isinstance(issue_request, IssueRequest):
            raise TypeError('Not a valid IssueRequest Object')

        if not check_subscriptions(pk, subscriptions):
            raise TypeError('Include unkown subscription in subscription list')
        
        # generate AttributeMap for issuer_attributes, the length is same as pk.attributes, but key's range is [1, L]
        issuer_attributes = generate_issuer_attributes(pk, subscriptions)
        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)

        return jsonpickle.encode(blind_signature, keys=True).encode()


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        disclosured_proof = jsonpickle.decode(signature, keys=True)

        if not isinstance(pk, PublicKey):
            raise TypeError('Not a valid PublicKey Object')
        
        if not isinstance(disclosured_proof, DisclosureProof):
            raise TypeError('Not a valid DisclosureProof Object')

        if not check_subscriptions(pk, revealed_attributes):
            raise TypeError('Include unkown subscription in subscription list')

        disclosed_attributes = generate_disclosed_attributes(pk, revealed_attributes)

        return verify_disclosure_proof(pk, disclosured_proof, disclosed_attributes, message)



class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.r = G1.order().random()

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)

        if not isinstance(pk, PublicKey):
          raise TypeError("Not a valid PublicKey Object")

        # initialize user attribute
        user_attributes = {1: self.r}
        issue_request, state = create_issue_request(pk, user_attributes)

        return jsonpickle.encode(issue_request, keys=True).encode(), state


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        blind_signature = jsonpickle.decode(server_response, keys=True)

        if not isinstance(pk, PublicKey):
          raise TypeError("Not a valid PublicKey Object")

        if not isinstance(blind_signature, BlindSignature):
          raise TypeError("Not a valid BlindSignature Object")      

        anon_credential = obtain_credential(pk, blind_signature, private_state)

        return jsonpickle.encode(anon_credential, keys=True).encode()


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        anon_credential = jsonpickle.decode(credentials, keys=True)

        if not isinstance(pk, PublicKey):
          raise TypeError("Not a valid PublicKey Object")

        if not isinstance(anon_credential, AnonymousCredential):
          raise TypeError("Not a valid AnonymousCredential Object")      

        hidden_attributes = generate_hidden_attrs(pk, types, anon_credential)
        
        disc_proof = create_disclosure_proof(pk,
                                             anon_credential,
                                             hidden_attributes, message)

        return jsonpickle.encode(disc_proof, keys=True).encode()

