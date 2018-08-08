package com.example.telco;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertTrue;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("test")
public class ApplicationTest {

    @Autowired
    ApplicationContext context;

    @Test
    public void testSuccessfulStartup() throws Exception {
        assertTrue(context.getBeanDefinitionCount() > 0);
    }
}
