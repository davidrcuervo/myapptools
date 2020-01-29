package com.laetienda.myapptools;

import java.util.HashMap;
import java.util.List;

public interface FormBeanInterface {
	
	public void addError(String list, String error);
	public HashMap<String, List<String>> getErrors();

}
