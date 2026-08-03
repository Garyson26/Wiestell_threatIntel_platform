'use client';

import { useState, useEffect } from 'react';
import AdminRoute from '@/components/auth/AdminRoute';
import { Mail, Calendar, User, MessageSquare, CheckCircle, Clock, AlertCircle, RefreshCw } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { getContactMessages, resolveContactMessage } from '@/lib/api';
import type { ContactMessage as Contact } from '@/lib/types';

const reasonLabels: Record<string, string> = {
  'feed-issue': 'Feed Issue',
  'api-access': 'API Access',
  'feature-request': 'Feature Request',
  'abuse-report': 'Abuse Report',
};

const reasonColors: Record<string, string> = {
  'feed-issue': 'bg-red-100 text-red-800 border-red-200',
  'api-access': 'bg-blue-100 text-blue-800 border-blue-200',
  'feature-request': 'bg-green-100 text-green-800 border-green-200',
  'abuse-report': 'bg-yellow-100 text-yellow-800 border-yellow-200',
};

const statusColors: Record<string, { icon: React.ElementType; color: string }> = {
  pending: { icon: Clock, color: 'text-yellow-600' },
  'in-progress': { icon: RefreshCw, color: 'text-blue-600' },
  resolved: { icon: CheckCircle, color: 'text-green-600' },
};

export default function ContactMessagesPage() {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [filter, setFilter] = useState<string>('all');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const fetchContacts = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Routed through the shared API client so the admin bearer token is sent.
      const params: Record<string, string> = { page: page.toString(), page_size: '50' };
      if (filter !== 'all') {
        params.status = filter;
      }

      const data = await getContactMessages(params);
      setContacts(data.contacts);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load contacts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchContacts();
  }, [page, filter]);

  const handleResolve = async (contactId: string) => {
    try {
      await resolveContactMessage(contactId, 'Resolved from admin panel');

      // Refresh the list
      fetchContacts();
      setSelectedContact(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resolve contact');
    }
  };

  return (
    <AdminRoute>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-display font-bold text-sentinel-text-primary">
              Contact Messages
            </h1>
            <p className="text-sm font-mono text-sentinel-text-muted mt-1">
              Manage user inquiries and support requests
            </p>
          </div>
          <button
            onClick={fetchContacts}
            className="flex items-center gap-2 px-4 py-2 text-sm font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="sentinel-card p-4">
            <p className="text-xs font-mono text-sentinel-text-muted uppercase">Total Messages</p>
            <p className="text-2xl font-display font-bold text-sentinel-text-primary mt-1">
              {total}
            </p>
          </div>
          <div className="sentinel-card p-4">
            <p className="text-xs font-mono text-sentinel-text-muted uppercase">Pending</p>
            <p className="text-2xl font-display font-bold text-yellow-600 mt-1">
              {contacts.filter(c => c.is_resolved === 'pending').length}
            </p>
          </div>
          <div className="sentinel-card p-4">
            <p className="text-xs font-mono text-sentinel-text-muted uppercase">In Progress</p>
            <p className="text-2xl font-display font-bold text-blue-600 mt-1">
              {contacts.filter(c => c.is_resolved === 'in-progress').length}
            </p>
          </div>
          <div className="sentinel-card p-4">
            <p className="text-xs font-mono text-sentinel-text-muted uppercase">Resolved</p>
            <p className="text-2xl font-display font-bold text-green-600 mt-1">
              {contacts.filter(c => c.is_resolved === 'resolved').length}
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-2">
          {['all', 'pending', 'in-progress', 'resolved'].map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-4 py-2 text-xs font-mono rounded border transition-colors ${
                filter === status
                  ? 'bg-sentinel-accent text-white border-sentinel-accent'
                  : 'bg-sentinel-bg-secondary text-sentinel-text-secondary border-sentinel-border hover:border-sentinel-accent'
              }`}
            >
              {status.toUpperCase().replace('-', ' ')}
            </button>
          ))}
        </div>

        {/* Error State */}
        {error && (
          <div className="sentinel-card p-4 border-red-200 bg-red-50">
            <p className="text-sm font-mono text-red-800">{error}</p>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="sentinel-card p-8 text-center">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-sentinel-text-muted" />
            <p className="text-sm font-mono text-sentinel-text-muted mt-2">Loading contacts...</p>
          </div>
        )}

        {/* Contacts Table */}
        {!loading && contacts.length === 0 && (
          <div className="sentinel-card p-8 text-center">
            <MessageSquare className="w-12 h-12 mx-auto text-sentinel-text-muted mb-3" />
            <p className="text-sm font-mono text-sentinel-text-muted">No contact messages found</p>
          </div>
        )}

        {!loading && contacts.length > 0 && (
          <div className="sentinel-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-sentinel-bg-tertiary border-b border-sentinel-border">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Status
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Name
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Email
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Reason
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Message Preview
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Submitted
                    </th>
                    <th className="px-4 py-3 text-center text-xs font-mono font-semibold text-sentinel-text-primary uppercase">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sentinel-border">
                  {contacts.map((contact) => {
                    const StatusIcon = statusColors[contact.is_resolved]?.icon || AlertCircle;
                    return (
                      <tr
                        key={contact.id}
                        className="hover:bg-sentinel-bg-secondary transition-colors"
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <StatusIcon className={`w-4 h-4 ${statusColors[contact.is_resolved]?.color || 'text-gray-600'}`} />
                            <span className="text-xs font-mono text-sentinel-text-secondary capitalize">
                              {contact.is_resolved.replace('-', ' ')}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm font-mono text-sentinel-text-primary">
                            {contact.name}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <a
                            href={`mailto:${contact.email}`}
                            className="text-sm font-mono text-sentinel-accent hover:underline"
                          >
                            {contact.email}
                          </a>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-block px-2 py-1 text-xs font-mono rounded border ${
                              reasonColors[contact.reason] || 'bg-gray-100 text-gray-800 border-gray-200'
                            }`}
                          >
                            {reasonLabels[contact.reason] || contact.reason}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-xs">
                          <p className="text-sm font-mono text-sentinel-text-secondary truncate">
                            {contact.message.substring(0, 80)}
                            {contact.message.length > 80 && '...'}
                          </p>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-sentinel-text-muted">
                            {formatDistanceToNow(new Date(contact.created_at), { addSuffix: true })}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <div className="flex items-center justify-center gap-2">
                            <button
                              onClick={() => setSelectedContact(contact)}
                              className="px-3 py-1 text-xs font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent transition-colors"
                            >
                              View
                            </button>
                            {contact.is_resolved !== 'resolved' && (
                              <button
                                onClick={() => handleResolve(contact.id)}
                                className="px-3 py-1 text-xs font-mono rounded bg-green-600 text-white hover:bg-green-700 transition-colors"
                              >
                                Resolve
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pagination */}
        {total > 50 && (
          <div className="flex justify-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-4 py-2 text-sm font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="px-4 py-2 text-sm font-mono text-sentinel-text-primary">
              Page {page} of {Math.ceil(total / 50)}
            </span>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={page >= Math.ceil(total / 50)}
              className="px-4 py-2 text-sm font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        )}

        {/* Detail Modal */}
        {selectedContact && (
          <div
            className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
            onClick={() => setSelectedContact(null)}
          >
            <div
              className="sentinel-card max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start justify-between mb-4">
                <h2 className="text-xl font-display font-bold text-sentinel-text-primary">
                  Contact Details
                </h2>
                <button
                  onClick={() => setSelectedContact(null)}
                  className="text-sentinel-text-muted hover:text-sentinel-text-primary"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Name</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1">
                    {selectedContact.name}
                  </p>
                </div>

                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Email</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1">
                    <a href={`mailto:${selectedContact.email}`} className="text-sentinel-accent hover:underline">
                      {selectedContact.email}
                    </a>
                  </p>
                </div>

                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Reason</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1">
                    {reasonLabels[selectedContact.reason] || selectedContact.reason}
                  </p>
                </div>

                {selectedContact.ioc && (
                  <div>
                    <label className="text-xs font-mono text-sentinel-text-muted uppercase">IOC / Indicator</label>
                    <p className="text-sm font-mono text-sentinel-text-primary mt-1 bg-sentinel-bg-tertiary p-2 rounded">
                      {selectedContact.ioc}
                    </p>
                  </div>
                )}

                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Message</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1 whitespace-pre-wrap bg-sentinel-bg-tertiary p-3 rounded leading-relaxed">
                    {selectedContact.message}
                  </p>
                </div>

                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Status</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1 capitalize">
                    {selectedContact.is_resolved.replace('-', ' ')}
                  </p>
                </div>

                <div>
                  <label className="text-xs font-mono text-sentinel-text-muted uppercase">Submitted</label>
                  <p className="text-sm font-mono text-sentinel-text-primary mt-1">
                    {new Date(selectedContact.created_at).toLocaleString()}
                  </p>
                </div>

                {selectedContact.resolved_at && (
                  <div>
                    <label className="text-xs font-mono text-sentinel-text-muted uppercase">Resolved</label>
                    <p className="text-sm font-mono text-sentinel-text-primary mt-1">
                      {new Date(selectedContact.resolved_at).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>

              <div className="mt-6 flex gap-3">
                {selectedContact.is_resolved !== 'resolved' && (
                  <button
                    onClick={() => handleResolve(selectedContact.id)}
                    className="flex-1 px-4 py-2 text-sm font-mono rounded bg-green-600 text-white hover:bg-green-700 transition-colors"
                  >
                    Mark as Resolved
                  </button>
                )}
                <button
                  onClick={() => setSelectedContact(null)}
                  className="flex-1 px-4 py-2 text-sm font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminRoute>
  );
}
