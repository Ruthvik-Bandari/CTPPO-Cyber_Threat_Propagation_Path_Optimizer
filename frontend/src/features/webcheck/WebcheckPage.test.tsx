import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import WebcheckPage, { NOTICE } from "./WebcheckPage";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <WebcheckPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("web check authorization gate", () => {
  it("keeps Scan disabled until the user confirms authorization", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    const scan = screen.getByRole<HTMLButtonElement>("button", { name: /scan/i });
    expect(screen.getByText(NOTICE)).toBeTruthy();

    fireEvent.change(screen.getByLabelText(/website address/i), { target: { value: "example.com" } });
    expect(scan.disabled).toBe(true);

    fireEvent.submit(scan.closest("form") as HTMLFormElement);
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("checkbox", { name: /i own this site or am authorized/i }));
    expect(scan.disabled).toBe(false);
  });

  it("stays disabled with authorization but no URL", () => {
    renderPage();
    fireEvent.click(screen.getByRole("checkbox", { name: /i own this site or am authorized/i }));
    expect(screen.getByRole<HTMLButtonElement>("button", { name: /scan/i }).disabled).toBe(true);
  });

  it("sends the URL (with https:// added) once authorized", async () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    fireEvent.change(screen.getByLabelText(/website address/i), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /i own this site or am authorized/i }));
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ url: "https://example.com", allow_private: false });
  });
});
