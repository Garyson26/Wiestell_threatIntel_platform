#!/usr/bin/env python3
"""Load MITRE ATT&CK Enterprise techniques into the database."""

import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.database import SyncSessionLocal, sync_engine, Base
from app.models.attack_technique import AttackTechnique
from app.feeds.mitre_attack import load_attack_data


async def load():
    print("Fetching MITRE ATT&CK Enterprise data...")
    techniques = await load_attack_data()
    
    if not techniques:
        print("No techniques loaded. Check network connectivity.")
        return
    
    Base.metadata.create_all(bind=sync_engine)
    session = SyncSessionLocal()
    
    try:
        count = 0
        for tech in techniques:
            existing = session.query(AttackTechnique).filter(
                AttackTechnique.id == tech["id"]
            ).first()
            
            if existing:
                existing.name = tech["name"]
                existing.tactic = tech["tactic"]
                existing.description = tech.get("description", "")
                existing.url = tech.get("url")
                existing.data_sources = tech.get("data_sources", [])
            else:
                session.add(AttackTechnique(
                    id=tech["id"],
                    name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech.get("description", ""),
                    url=tech.get("url"),
                    data_sources=tech.get("data_sources", []),
                ))
                count += 1
        
        session.commit()
        print(f"Loaded {count} new techniques ({len(techniques)} total) into the database.")
    except Exception as e:
        session.rollback()
        print(f"Error loading MITRE data: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    print("Loading MITRE ATT&CK Enterprise data...")
    asyncio.run(load())
