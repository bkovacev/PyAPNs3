import time
from typing import Optional, Tuple, TYPE_CHECKING

import jwt
import httpx

DEFAULT_TOKEN_LIFETIME = 2700
DEFAULT_TOKEN_ENCRYPTION_ALGORITHM = 'ES256'


# Abstract Base class. This should not be instantiated directly.
class Credentials(object):
    def create_connection(self, server: str, port: int) -> httpx.Client:
        return httpx.Client(base_url=f"https://{server}:{port}", http2=True)

    def get_authorization_header(self, topic: Optional[str]) -> Optional[str]:
        return None


# Credentials subclass for certificate authentication
class CertificateCredentials(Credentials):
    def __init__(self, cert_file: Optional[str] = None, password: Optional[str] = None,
                 cert_chain: Optional[str] = None) -> None:
        self.cert_file = cert_file
        self.cert_chain = cert_chain
        super(CertificateCredentials, self).__init__()

    def create_connection(self, server: str, port: int) -> httpx.Client:
        # If a cert_chain is provided, both cert and key are in the chain. Otherwise, they're separate.
        if self.cert_chain:
            return httpx.Client(base_url=f"https://{server}:{port}", http2=True, cert=self.cert_chain)
        return httpx.Client(base_url=f"https://{server}:{port}", http2=True, cert=self.cert_file)


# Credentials subclass for JWT token based authentication
class TokenCredentials(Credentials):
    def __init__(self, auth_key_path: str, auth_key_id: str, team_id: str,
                 encryption_algorithm: str = DEFAULT_TOKEN_ENCRYPTION_ALGORITHM,
                 token_lifetime: int = DEFAULT_TOKEN_LIFETIME) -> None:
        self.__auth_key = self._get_signing_key(auth_key_path)
        self.__auth_key_id = auth_key_id
        self.__team_id = team_id
        self.__encryption_algorithm = encryption_algorithm
        self.__token_lifetime = token_lifetime
        self.__jwt_token = None  # type: Optional[Tuple[float, str]]
        super(TokenCredentials, self).__init__()

    def get_authorization_header(self, topic: Optional[str]) -> str:
        token = self._get_or_create_topic_token()
        return f'bearer {token}'

    def _is_expired_token(self, issue_date: float) -> bool:
        return time.time() > issue_date + self.__token_lifetime

    @staticmethod
    def _get_signing_key(key_path: str) -> str:
        secret = ''
        if key_path:
            with open(key_path) as f:
                secret = f.read()
        return secret

    def _get_or_create_topic_token(self) -> str:
        token_pair = self.__jwt_token
        if token_pair is None or self._is_expired_token(token_pair[0]):
            issued_at = time.time()
            token_dict = {'iss': self.__team_id, 'iat': issued_at}
            headers = {'alg': self.__encryption_algorithm, 'kid': self.__auth_key_id}
            jwt_token = jwt.encode(token_dict, self.__auth_key,
                                   algorithm=self.__encryption_algorithm,
                                   headers=headers)
            self.__jwt_token = (issued_at, jwt_token)
            return jwt_token
        else:
            return token_pair[1]
