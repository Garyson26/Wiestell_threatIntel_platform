"""API router registration."""

from fastapi import APIRouter
from app.api import ioc, feeds, enrichment, dashboard, reports, attack, users, ai

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(ioc.router, prefix="/iocs", tags=["IOCs"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["Feeds"])
api_router.include_router(enrichment.router, prefix="/enrichment", tags=["Enrichment"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(attack.router, prefix="/attack", tags=["ATT&CK"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(ai.router, prefix="/ai", tags=["AI"])
