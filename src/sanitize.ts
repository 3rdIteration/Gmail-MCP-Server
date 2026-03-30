/**
 * HTML sanitization utilities for email content.
 *
 * Emails are untrusted, attacker-controlled content that flows into an LLM's
 * context window via MCP tool responses.  Attackers can embed invisible text
 * (zero-font, display:none, HTML comments, white-on-white, etc.) that is
 * invisible to humans but visible when the HTML is naively converted to text.
 *
 * This module strips those vectors before email content reaches the LLM.
 */

/**
 * Strip HTML tags and decode common HTML entities to produce safe plain text.
 *
 * The function removes:
 *   - <script>, <style>, <head> blocks entirely
 *   - HTML comments (<!-- ... -->)
 *   - Elements with hidden CSS: display:none, visibility:hidden, font-size:0,
 *     opacity:0, width:0/height:0, max-height:0 with overflow:hidden
 *   - All remaining HTML tags
 *
 * It then collapses excessive whitespace.
 */
export function stripHtml(html: string): string {
    if (!html) return '';

    let text = html;

    // 1. Remove <script>, <style>, and <head> blocks (including content)
    text = text.replace(/<script[\s\S]*?<\/script>/gi, '');
    text = text.replace(/<style[\s\S]*?<\/style>/gi, '');
    text = text.replace(/<head[\s\S]*?<\/head>/gi, '');

    // 2. Remove HTML comments (<!-- ... -->), including multi-line
    text = text.replace(/<!--[\s\S]*?-->/g, '');

    // 3. Remove elements whose inline style hides content from humans.
    //    This targets the most common prompt-injection attack vectors:
    //    display:none, visibility:hidden, font-size:0, opacity:0,
    //    max-height:0, overflow:hidden.
    //
    //    We use pre-built regexes (not new RegExp) to avoid escaping issues.

    // Helper: for each hidden-style pattern, remove matching elements + content
    // Handles double-quoted style attributes
    const hiddenPatterns: RegExp[] = [
        // display:none  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // display:none  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*display\s*:\s*none[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
        // visibility:hidden  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*visibility\s*:\s*hidden[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // visibility:hidden  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*visibility\s*:\s*hidden[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
        // font-size:0  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*font-size\s*:\s*0[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // font-size:0  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*font-size\s*:\s*0[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
        // opacity:0  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*opacity\s*:\s*0[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // opacity:0  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*opacity\s*:\s*0[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
        // max-height:0  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*max-height\s*:\s*0[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // max-height:0  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*max-height\s*:\s*0[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
        // overflow:hidden  (double-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*"[^"]*overflow\s*:\s*hidden[^"]*"[^>]*>[\s\S]*?<\/\1>/gi,
        // overflow:hidden  (single-quoted)
        /<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*'[^']*overflow\s*:\s*hidden[^']*'[^>]*>[\s\S]*?<\/\1>/gi,
    ];

    for (const re of hiddenPatterns) {
        text = text.replace(re, '');
    }

    // 4. Convert common block-level elements to newlines for readability
    text = text.replace(/<br\s*\/?>/gi, '\n');
    text = text.replace(/<\/?(p|div|tr|li|h[1-6]|blockquote|pre)\b[^>]*>/gi, '\n');

    // 5. Strip all remaining HTML tags
    text = text.replace(/<[^>]+>/g, '');

    // 6. Decode common HTML entities
    text = text.replace(/&nbsp;/gi, ' ');
    text = text.replace(/&amp;/gi, '&');
    text = text.replace(/&lt;/gi, '<');
    text = text.replace(/&gt;/gi, '>');
    text = text.replace(/&quot;/gi, '"');
    text = text.replace(/&#39;/gi, "'");
    text = text.replace(/&#x27;/gi, "'");
    text = text.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)));
    text = text.replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)));

    // 7. Collapse whitespace: multiple blank lines → two newlines, trim lines
    text = text.replace(/[ \t]+/g, ' ');
    text = text.replace(/\n\s*\n/g, '\n\n');
    text = text.trim();

    return text;
}

/**
 * Wrap untrusted email content with clearly marked boundary delimiters so the
 * LLM can distinguish email data from MCP system instructions.
 *
 * The delimiters follow a consistent format that is unlikely to appear in
 * legitimate email content.
 */
export function frameEmailContent(label: string, content: string): string {
    const boundary = '─'.repeat(40);
    return `${boundary}\n[BEGIN EMAIL ${label}]\n${boundary}\n${content}\n${boundary}\n[END EMAIL ${label}]\n${boundary}`;
}

/**
 * Truncate a string to a maximum length, appending an indicator if truncated.
 */
export function truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + '… [truncated]';
}

/**
 * Sanitize an error message to avoid leaking sensitive details.
 * Strips file paths, token-like strings, and stack traces.
 */
export function sanitizeErrorMessage(message: string): string {
    let safe = message;

    // Strip absolute file paths (Unix and Windows)
    safe = safe.replace(/(?:\/[\w.-]+){2,}/g, '[path]');
    safe = safe.replace(/[A-Z]:\\[\w\\.-]+/g, '[path]');

    // Strip long base64 or token-like strings (40+ chars of base64 alphabet)
    safe = safe.replace(/[A-Za-z0-9+/=_-]{40,}/g, '[redacted]');

    // Strip anything that looks like a bearer token or API key
    safe = safe.replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');

    return safe;
}
