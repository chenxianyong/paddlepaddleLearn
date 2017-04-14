package test;

import org.junit.Test;

public class TestLucene {
	
	@Test
	public void testIndex(){
		HelloLucene hl = new HelloLucene();
		hl.index();
	}
}
