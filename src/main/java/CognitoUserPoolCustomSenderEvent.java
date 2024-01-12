import com.amazonaws.services.lambda.runtime.events.CognitoUserPoolEvent;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import java.util.Map;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
public class CognitoUserPoolCustomSenderEvent extends CognitoUserPoolEvent {

    private Request request;

    @Builder(setterPrefix = "with")
    public CognitoUserPoolCustomSenderEvent(
            String version,
            String triggerSource,
            String region,
            String userPoolId,
            String userName,
            CallerContext callerContext,
            Request request
    ) {
        super(version, triggerSource, region, userPoolId, userName, callerContext);
        this.request = request;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @NoArgsConstructor
    public static class Request extends CognitoUserPoolEvent.Request {

        private String type;

        private Map<String, String> clientMetadata;

        private String code;

        @Builder(setterPrefix = "with")
        public Request(Map<String, String> userAttributes, String type, Map<String, String> clientMetadata, String code) {
            super(userAttributes);
            this.type = type;
            this.clientMetadata = clientMetadata;
            this.code = code;
        }
    }
}
