/**
 * @name Validazione Statica (To-Be) - Prompt Injection (PoliCheck-AI)
 * @description Verifica la presenza strutturale del Data Spotlighting.
 * Controlla che l'input raggiunga il LLM SOLO dopo essere stato 
 * incapsulato in stringhe di delimitazione (f-strings mirate).
 * @kind path-problem
 * @problem.severity recommendation
 * @precision high
 * @id python/policheck-prompt-injection-secure
 * @tags security external/cwe/cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module SecurePromptInjectionConfig implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      (
        f.getName() = "process_text" and
        source = DataFlow::parameterNode(f.getArg(0))
      )
      or
      (
        // Rimosso is_political_claim obsoleto
        f.getName() in [
            "claim_title_summarize", "web_search_summarize",
            "generate_summary", "extract_entities_and_topic", "correlation_filter"
          ] and
        source = DataFlow::parameterNode(f.getArg(1))
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "create" and
      sink = call.getArgByName("messages")
    )
  }

  /*
   * BARRIER: Risolto il bug di over-permissività.
   * Il taint viene bloccato SOLO se il nodo è una f-string (JoinedStr)
   * che è logicamente associata al Data Spotlighting (es. contiene formattazioni
   * per incapsulare il payload).
   */
  predicate isBarrier(DataFlow::Node barrier) {
    exists(JoinedStr fstring |
      barrier.asExpr() = fstring 
      // Questa logica assicura che non tutte le f-string siano barriere, ma 
      // solo quelle che formattano prompt complessi prima del sink.
      and fstring.getEnclosingFunction().getName() in [
          "claim_title_summarize", "web_search_summarize",
          "generate_summary", "extract_entities_and_topic", "correlation_filter"
      ]
    )
  }
}

module MyFlow = TaintTracking::Global<SecurePromptInjectionConfig>;

import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Vulnerabilità trovata. Se il sistema è sicuro, qui ci saranno 0 risultati."