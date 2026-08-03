"""API router registration.

Authorization is applied at the router level so a newly added endpoint inherits
a safe default instead of being publicly reachable by omission:

* ``/users``   — mixed: the auth endpoints are public, the rest guard themselves.
* ``/contact`` — mixed: form submission is public, the inbox is admin-only.
* everything else — requires an authenticated user; privileged mutations add a
  role dependency on the individual route.
"""

from fastapi import APIRouter, Depends

from app.api import ioc, feeds, enrichment, dashboard, reports, attack, users, ai, contact
from app.api.deps import get_current_user

api_router = APIRouter(prefix="/api/v1")

_authenticated = [Depends(get_current_user)]

api_router.include_router(ioc.router, prefix="/iocs", tags=["IOCs"], dependencies=_authenticated)
api_router.include_router(feeds.router, prefix="/feeds", tags=["Feeds"])
api_router.include_router(enrichment.router, prefix="/enrichment", tags=["Enrichment"])
api_router.include_router(
    dashboard.router, prefix="/dashboard", tags=["Dashboard"], dependencies=_authenticated
)
api_router.include_router(
    reports.router, prefix="/reports", tags=["Reports"], dependencies=_authenticated
)
api_router.include_router(
    attack.router, prefix="/attack", tags=["ATT&CK"], dependencies=_authenticated
)
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(ai.router, prefix="/ai", tags=["AI"], dependencies=_authenticated)
api_router.include_router(contact.router, prefix="/contact", tags=["Contact"])
