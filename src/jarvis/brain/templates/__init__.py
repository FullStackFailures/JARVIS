from jarvis.brain.templates.apps_t import AppsTemplate
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.brain.templates.conversation import ConversationTemplate
from jarvis.brain.templates.deferred import DeferredTemplate
from jarvis.brain.templates.files_t import FilesTemplate
from jarvis.brain.templates.ops_t import (
    AppStatusTemplate,
    FileReadTemplate,
    FileSearchTemplate,
    NotesTemplate,
    PortOwnerTemplate,
    ProcessListTemplate,
    ServiceStatusTemplate,
)
from jarvis.brain.templates.system_t import SystemFactsTemplate
from jarvis.brain.templates.terminal_t import TerminalTemplate


def default_templates() -> list[GoalTemplate]:
    return [
        ConversationTemplate(),
        TerminalTemplate(),
        PortOwnerTemplate(),
        ServiceStatusTemplate(),
        AppStatusTemplate(),
        ProcessListTemplate(),
        NotesTemplate(),
        FileReadTemplate(),
        FileSearchTemplate(),
        SystemFactsTemplate(),
        FilesTemplate(),
        AppsTemplate(),
        DeferredTemplate(),
    ]


__all__ = ["Built", "GoalTemplate", "RouteContext", "default_templates"]
