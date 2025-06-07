package org.example.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EncryptedMessage {
    private String message;
    private String method;
    private String key;
}