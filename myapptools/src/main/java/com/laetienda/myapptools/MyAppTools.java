package com.laetienda.myapptools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Hello world!
 *
 */
public class MyAppTools

{
	private static final Logger log = LogManager.getLogger(MyAppTools.class);
	
	public HashMap<String, List<String>> addError(String list, String error, HashMap<String, List<String>> errors){
		
		List<String> errorList;
		
		if(errors.get(list) == null){
			errorList = new ArrayList<String>();
		} else{
			errorList = errors.get(list);			
		}
		
		errorList.add(error);
		errors.put(list, errorList);
		log.warn("User input error. $errorList: {} - $error: {}", list, error);
		return errors;
	}
	
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }
}
