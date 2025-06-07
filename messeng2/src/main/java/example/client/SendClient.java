package example.client;

import example.model.EncryptedMessage;
import example.model.SendKey;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;


@FeignClient(name = "host2", url = "http://localhost:8080")
public interface SendClient {

    @PostMapping("/api/accept_messange")
    void acceptMessange(@RequestBody EncryptedMessage encryptedMessage);

    @PostMapping("/api/get_public_key")
    void getPublicKey(@RequestBody SendKey encryptedMessage);

}
