"""The delivery port. Implement [EmailSender.send][crudauth.email.sender.EmailSender.send] for your transport."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .constants import EMAIL_KINDS, EmailKind

__all__ = ["EmailSender", "EmailContext", "EmailKind", "EMAIL_KINDS"]


@dataclass(frozen=True)
class EmailContext:
    """crudauth-owned render data handed to [EmailSender.send][crudauth.email.sender.EmailSender.send].

    Everything a sender needs to render its own HTML around crudauth's recovery
    flow, and *nothing else*. Specifically it carries the assembled ``link`` (the
    signed token is already embedded in the URL, which is what gets emailed), not
    the bare token, and it carries **no user-controlled fields** (no ``username``,
    no ``email``). That is deliberate: a sender drops these values into HTML, so
    crudauth keeps anything injectable out of reach and is never the XSS vector.

    For per-user personalization (``Hi Alice``), write a
    [DeliveryChannel][crudauth.email.channel.DeliveryChannel] instead: it receives
    the ``db`` handle and the user row, and owns its own escaping.

    Attributes:
        kind: Which message this is - one of :data:`EMAIL_KINDS`.
        link: The assembled, ready-to-click URL with the token embedded, or
            ``None`` for ``existing_account`` (a notice with no action).
        recipient: The destination address crudauth resolved.
        expires_in: Token lifetime in seconds, or ``0`` when ``link`` is ``None``.

    Example:
        ```python
        # inside EmailSender.send, render your own HTML from the context:
        html = f'<a href="{context.link}">Verify your email</a>'
        ```
    """

    kind: EmailKind
    link: str | None
    recipient: str
    expires_in: int


class EmailSender(ABC):
    """Adapter crudauth calls to deliver a message.

    crudauth composes the subject and a plain-text ``body`` (with the signed-token
    link in it) and hands them to you; you decide how to deliver (SMTP, SES, a task
    queue...). For a plain sender, deliver ``body`` as-is. To send your own HTML,
    read [context][crudauth.email.sender.EmailContext] - ``context.link`` is the
    assembled URL, so you can build a real ``<a href>`` button or branded template
    without regexing the link out of ``body``.

    ``context`` carries crudauth-owned render data only (link, kind, expiry,
    recipient), never the bare token and never user-controlled fields. For per-user
    personalization, write a [DeliveryChannel][crudauth.email.channel.DeliveryChannel]
    (it has ``db`` and owns escaping) rather than reaching for user data here.

    Example:
        ```python
        class MyEmailSender(EmailSender):
            async def send(self, *, to, subject, body, kind, context):
                # plain: deliver crudauth's text as-is.
                # html:  build your own from context.link.
                html = render(f"{kind}.html", link=context.link) if context.link else body
                await my_task_queue.enqueue(send_email, to=to, subject=subject, html=html)
        ```
    """

    @abstractmethod
    async def send(
        self, *, to: str, subject: str, body: str, kind: EmailKind, context: EmailContext
    ) -> None:
        """Deliver one message.

        Args:
            to: Recipient address.
            subject: Message subject crudauth composed.
            body: Plain-text message body crudauth composed, including the
                signed-token link. Deliver it as-is for a plain sender, or ignore
                it and render your own from ``context``.
            kind: Which message this is - one of :data:`EMAIL_KINDS`. Use it to
                select the template (``existing_account`` is a security notice,
                not a welcome).
            context: crudauth-owned render data
                ([EmailContext][crudauth.email.sender.EmailContext]): the assembled
                ``link``, ``kind``, ``recipient``, and ``expires_in``. Read
                ``context.link`` to build HTML. It carries no bare token and no
                user-controlled fields by design.

        Note:
            Prefer to **enqueue** (hand off to a task queue) rather than block on
            SMTP/provider I/O here. crudauth treats the registration sends as
            best-effort (a failure is logged, not surfaced), but other flows may
            propagate a raised send as a 5xx - a non-blocking adapter avoids both
            slow requests and transient-failure errors.
        """
        raise NotImplementedError
