package rsa.main;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;

public class DebugLogger {
   private MessageContext msgContext;
   private ExecutionContext execContext;

   public DebugLogger() {
   }

   public DebugLogger(MessageContext msgContext, ExecutionContext execContext) {
      this.msgContext = msgContext;
      this.execContext = execContext;
   }

   public void log(String variable, String value) {
      this.msgContext.setVariable(variable, value);
   }
}
