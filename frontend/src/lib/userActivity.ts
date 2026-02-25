import type { IOC } from './types';

export interface UserActivity {
  id: string;
  userId: string;
  type: 'search' | 'submit' | 'view';
  iocValue?: string;
  iocType?: string;
  iocId?: string;
  threatScore?: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface UserStats {
  totalSearches: number;
  totalSubmissions: number;
  totalViews: number;
  recentActivities: UserActivity[];
  criticalIOCs: number;
  highThreatIOCs: number;
  averageThreatScore: number;
  lastActivityTime: string | null;
}

const STORAGE_KEY = 'sentinel_user_activities';
const MAX_ACTIVITIES = 500; // Keep last 500 activities per user

// Get all activities for a specific user
export function getUserActivities(userId: string): UserActivity[] {
  if (typeof window === 'undefined') return [];
  
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    
    const allActivities: UserActivity[] = JSON.parse(stored);
    return allActivities.filter(a => a.userId === userId);
  } catch (error) {
    console.error('Error reading user activities:', error);
    return [];
  }
}

// Add a new activity
export function addUserActivity(
  userId: string,
  type: UserActivity['type'],
  data: Partial<Omit<UserActivity, 'id' | 'userId' | 'type' | 'timestamp'>>
): void {
  if (typeof window === 'undefined') return;
  
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    const allActivities: UserActivity[] = stored ? JSON.parse(stored) : [];
    
    const newActivity: UserActivity = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type,
      timestamp: new Date().toISOString(),
      ...data,
    };
    
    // Add new activity
    allActivities.unshift(newActivity);
    
    // Keep only MAX_ACTIVITIES per user
    const userActivitiesCount: Record<string, number> = {};
    const filteredActivities = allActivities.filter(activity => {
      userActivitiesCount[activity.userId] = (userActivitiesCount[activity.userId] || 0) + 1;
      return userActivitiesCount[activity.userId] <= MAX_ACTIVITIES;
    });
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filteredActivities));
  } catch (error) {
    console.error('Error saving user activity:', error);
  }
}

// Track IOC search
export function trackSearch(userId: string, query: string, resultsCount: number): void {
  addUserActivity(userId, 'search', {
    metadata: {
      query,
      resultsCount,
    },
  });
}

// Track IOC submission
export function trackSubmission(userId: string, iocs: IOC[]): void {
  // Track overall submission
  addUserActivity(userId, 'submit', {
    metadata: {
      count: iocs.length,
      types: Array.from(new Set(iocs.map(i => i.type))),
    },
  });
  
  // Track individual IOCs for statistics
  iocs.forEach(ioc => {
    addUserActivity(userId, 'submit', {
      iocValue: ioc.value,
      iocType: ioc.type,
      iocId: ioc.id,
      threatScore: ioc.threat_score,
    });
  });
}

// Track IOC view
export function trackView(userId: string, ioc: IOC | { id: string; value: string; type: string; threat_score: number }): void {
  addUserActivity(userId, 'view', {
    iocValue: ioc.value,
    iocType: ioc.type,
    iocId: ioc.id,
    threatScore: ioc.threat_score,
  });
}

// Get user statistics
export function getUserStats(userId: string): UserStats {
  const activities = getUserActivities(userId);
  
  const searches = activities.filter(a => a.type === 'search');
  const submissions = activities.filter(a => a.type === 'submit' && a.iocId); // Only individual IOCs
  const views = activities.filter(a => a.type === 'view');
  
  const iocsWithScores = activities.filter(a => a.threatScore !== undefined && a.iocId);
  const criticalIOCs = iocsWithScores.filter(a => a.threatScore! >= 80).length;
  const highThreatIOCs = iocsWithScores.filter(a => a.threatScore! >= 60 && a.threatScore! < 80).length;
  
  const averageThreatScore = iocsWithScores.length > 0
    ? iocsWithScores.reduce((sum, a) => sum + (a.threatScore || 0), 0) / iocsWithScores.length
    : 0;
  
  const lastActivity = activities.length > 0 ? activities[0].timestamp : null;
  
  return {
    totalSearches: searches.length,
    totalSubmissions: submissions.length,
    totalViews: views.length,
    recentActivities: activities.slice(0, 50), // Last 50 activities
    criticalIOCs,
    highThreatIOCs,
    averageThreatScore: Math.round(averageThreatScore),
    lastActivityTime: lastActivity,
  };
}

// Get recent IOCs viewed/submitted by user
export function getRecentIOCs(userId: string, limit: number = 20): UserActivity[] {
  const activities = getUserActivities(userId);
  return activities
    .filter(a => (a.type === 'view' || a.type === 'submit') && a.iocId)
    .slice(0, limit);
}

// Clear user activities
export function clearUserActivities(userId: string): void {
  if (typeof window === 'undefined') return;
  
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return;
    
    const allActivities: UserActivity[] = JSON.parse(stored);
    const filteredActivities = allActivities.filter(a => a.userId !== userId);
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filteredActivities));
  } catch (error) {
    console.error('Error clearing user activities:', error);
  }
}

// Get activity summary by date (last 7 days)
export function getActivityTrend(userId: string, days: number = 7): Array<{ date: string; count: number }> {
  const activities = getUserActivities(userId);
  const today = new Date();
  const trend: Array<{ date: string; count: number }> = [];
  
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    const count = activities.filter(a => 
      a.timestamp.startsWith(dateStr)
    ).length;
    
    trend.push({ date: dateStr, count });
  }
  
  return trend;
}
