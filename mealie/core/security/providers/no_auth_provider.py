from datetime import timedelta

from sqlalchemy.orm.session import Session

from mealie.core import root_logger
from mealie.core.config import get_app_settings
from mealie.core.exceptions import UserLockedOut
from mealie.core.security.hasher import get_hasher
from mealie.core.security.providers.auth_provider import AuthProvider
from mealie.repos.all_repositories import get_repositories
from mealie.schema.user.auth import CredentialsRequest
from mealie.services.user_services.user_service import UserService


class NoAuthProvider(AuthProvider[CredentialsRequest]):
    """Authentication provider that authenticates a user the database using username/password combination"""

    _logger = root_logger.get_logger("credentials_provider")

    def __init__(self, session: Session, data: CredentialsRequest) -> None:
        super().__init__(session, data)

    async def authenticate(self) -> tuple[str, timedelta] | None:
        """Attempt to authenticate a user given a username and password"""
        settings = get_app_settings()
        db = get_repositories(self.session)
        users = db.users.get_all(limit=1)
        if users.count == 0:
            pass

        return self.get_access_token(users[0], True)  # type: ignore
