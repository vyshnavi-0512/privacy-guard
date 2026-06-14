import { useQuery, useMutation } from "@tanstack/react-query";
import type { UseQueryOptions, UseMutationOptions } from "@tanstack/react-query";
import { auth } from "../../firebase";
const API_URL = import.meta.env.VITE_API_URL;
import type {
  ScanInput, ScanResult, ScanSummary, AdvisorInput, AdvisorResponse,
  DashboardSummary, BreachCategory, MonitorInput, Monitor, BreachAlert,
  DeleteResult, PasswordCheckInput, PasswordCheckResult, MonitorScanResult,
} from "./api-schemas";

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");

  const currentUser = auth.currentUser;
  if (currentUser) {
    const token = await currentUser.getIdToken();
    headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(url, { ...init, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(err.error ?? res.statusText), { status: res.status, response: { data: err } });
  }
  return res.json();
}

// ── Query keys ──────────────────────────────────────────────────────────────
export const getGetDashboardSummaryQueryKey = () => ["/api/dashboard/summary"] as const;
export const getGetBreachCategoriesQueryKey = () => ["/api/dashboard/breach-categories"] as const;
export const getGetScanHistoryQueryKey = () => ["/api/scans/history"] as const;
export const getListMonitorsQueryKey = () => ["/api/monitors"] as const;
export const getListAlertsQueryKey = () => ["/api/monitors/alerts"] as const;

// ── Queries ──────────────────────────────────────────────────────────────────
export function useGetDashboardSummary(options?: Partial<UseQueryOptions<DashboardSummary>>) {
  return useQuery<DashboardSummary>({ queryKey: getGetDashboardSummaryQueryKey(), queryFn: ({ signal }) =>apiFetch(`${API_URL}/api/dashboard/summary`, { signal }), ...options });
}

export function useGetBreachCategories(options?: Partial<UseQueryOptions<BreachCategory[]>>) {
  return useQuery<BreachCategory[]>({ queryKey: getGetBreachCategoriesQueryKey(), queryFn: ({ signal }) => apiFetch(`${API_URL}/api/dashboard/breach-categories`, { signal }), ...options });
}

export function useGetScanHistory(options?: Partial<UseQueryOptions<ScanSummary[]>>) {
  return useQuery<ScanSummary[]>({ queryKey: getGetScanHistoryQueryKey(), queryFn: ({ signal }) => apiFetch(`${API_URL}/api/scans/history`, { signal }), ...options });
}

export function useListMonitors(options?: Partial<UseQueryOptions<Monitor[]>>) {
  return useQuery<Monitor[]>({ queryKey: getListMonitorsQueryKey(), queryFn: ({ signal }) => apiFetch(`${API_URL}/api/monitors`, { signal }), ...options });
}

export function useListAlerts(options?: Partial<UseQueryOptions<BreachAlert[]>>) {
  return useQuery<BreachAlert[]>({ queryKey: getListAlertsQueryKey(), queryFn: ({ signal }) => apiFetch(`${API_URL}/api/monitors/alerts`, { signal }), ...options });
}

// ── Mutations ─────────────────────────────────────────────────────────────────
export function useCreateScan(options?: Partial<UseMutationOptions<ScanResult, Error, { data: ScanInput }>>) {
  return useMutation<ScanResult, Error, { data: ScanInput }>({
    mutationFn: ({ data }) => apiFetch(`${API_URL}/api/scans`, {method: "POST", body: JSON.stringify(data) }),
    ...options,
  });
}

export function useGetAiRecommendations(options?: Partial<UseMutationOptions<AdvisorResponse, Error, { data: AdvisorInput }>>) {
  return useMutation<AdvisorResponse, Error, { data: AdvisorInput }>({
    mutationFn: ({ data }) => apiFetch(`${API_URL}/api/advisor/recommend`, { method: "POST", body: JSON.stringify(data) }),
    ...options,
  });
}

export function useCreateMonitor(options?: Partial<UseMutationOptions<Monitor, Error, { data: MonitorInput }>>) {
  return useMutation<Monitor, Error, { data: MonitorInput }>({
    mutationFn: ({ data }) => apiFetch(`${API_URL}/api/monitors`, { method: "POST", body: JSON.stringify(data) }),
    ...options,
  });
}

export function useDeleteMonitor(options?: Partial<UseMutationOptions<DeleteResult, Error, { id: string }>>) {
  return useMutation<DeleteResult, Error, { id: string }>({
    mutationFn: ({ id }) => apiFetch(`${API_URL}/api/monitors/${id}`, { method: "DELETE" }),
    ...options,
  });
}

export function useTriggerMonitorScan(options?: Partial<UseMutationOptions<MonitorScanResult, Error, { id: string }>>) {
  return useMutation<MonitorScanResult, Error, { id: string }>({
    mutationFn: ({ id }) => apiFetch(`${API_URL}/api/monitors/${id}/scan`, { method: "POST" }),
    ...options,
  });
}

export function useCheckPassword(options?: Partial<UseMutationOptions<PasswordCheckResult, Error, { data: PasswordCheckInput }>>) {
  return useMutation<PasswordCheckResult, Error, { data: PasswordCheckInput }>({
    mutationFn: ({ data }) => apiFetch(`${API_URL}/api/passwords/check`, { method: "POST", body: JSON.stringify(data) }),
    ...options,
  });
}

export type { ScanResult, AdvisorResponse };
