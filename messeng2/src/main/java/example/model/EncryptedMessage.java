package example.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EncryptedMessage {
    private String message;
    private String method;
    private String key;
}