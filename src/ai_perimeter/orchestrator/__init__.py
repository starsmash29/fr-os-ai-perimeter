"""The Natural Language Network Orchestrator (work package A2).

An admin's intent becomes a *proposal*, never a change:

1. the model sees the intent and a redacted summary of the config
   (:mod:`.prompt`) and answers with a patch in a closed JSON format
   (:mod:`.ops`): a handful of named operations, nothing else;
2. the patch is applied to a copy of the config (:func:`.ops.apply_patch`),
   the deny list in code refuses what no model may propose (:mod:`.deny`),
   FR_OS's own validator and rule linter check the result, and the admin
   gets a summary, a YAML diff and the findings (:mod:`.pipeline`);
3. saving is not here: the webUI replays the same operations on the real
   config and saves through FR_OS's apply-helper, with commit-confirm
   rollback (work package A3).
"""
