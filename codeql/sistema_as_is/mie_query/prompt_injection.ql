/**
 * @name Tracciamento statico della Prompt Injection (PoliCheck-AI)
 * @description Traccia come il testo non fidato (claim utente, articolo scrapato,
 *              entità estratte) fluisce senza sanificazione fino alle chiamate
 *              API di GroqCloud (self.client.chat.completions.create), dimostrando
 *              staticamente la superficie di attacco per Prompt Injection nella
 *              versione As-Is del sistema.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id python/policheck-prompt-injection
 * @tags security external/cwe/cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module PromptInjectionConfig implements DataFlow::ConfigSig {
  /*
   * SOURCE: parametri testuali non fidati che, nella versione As-Is, vengono
   * inseriti direttamente nei messaggi inviati a Groq senza alcun controllo
   * o delimitatore (NeMo Guardrails / Data Spotlighting non ancora presenti).
   */
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      (
        // backend.py: funzione libera, primo parametro = input_text
        f.getName() = "process_text" and
        source = DataFlow::parameterNode(f.getArg(0))
      )
      or
      (
        // Metodi di classe: self=arg0, testo non fidato=arg1
        f.getName() in [
            "is_political_claim", "claim_title_summarize", "web_search_summarize",
            "generate_summary", "extract_entities_and_topic", "correlation_filter"
          ] and
        source = DataFlow::parameterNode(f.getArg(1))
      )
    )
  }

  /*
   * SINK: l'argomento "messages" passato a una qualsiasi chiamata
   * `....chat.completions.create(...)` verso l'API Groq.
   */
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "create" and
      sink = call.getArgByName("messages")
    )
  }
}

module MyFlow = TaintTracking::Global<PromptInjectionConfig>;

import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Vulnerabilità rilevata staticamente: il testo non fidato raggiunge l'API Groq senza sanificazione, aprendo la strada a Prompt Injection."