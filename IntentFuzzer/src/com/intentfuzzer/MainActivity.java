package com.intentfuzzer;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		Intent intent = getIntent();
		String packageName = intent.getStringExtra("packageName");
		String componentName = intent.getStringExtra("componentName");
		String componentType = intent.getStringExtra("componentType");
		String intentType = intent.getStringExtra("intentType");
		
		if(packageName != null){
			if(intentType.equals("empty")){
				fuzzWithNullIntent(componentType, packageName, componentName);
			}else{
				fuzzWithSerializableIntent(componentType, packageName, componentName);
			}
		}
	}
	
	public void fuzzWithNullIntent(String componentType, String packageName, String componentName){
		Intent intent = new Intent();
		intent.setComponent(new ComponentName(packageName, componentName));
		
		Toast.makeText(getApplicationContext(), "Send Null Intent " + intent, Toast.LENGTH_LONG).show();
		if(componentType.equals("activity")){
			startActivity(intent);
		}else if(componentType.equals("receiver")){
			sendBroadcast(intent);
		}else if(componentType.equals("service")){
			startService(intent); 
		}
	}
	
	public void fuzzWithSerializableIntent(String componentType, String packageName, String componentName){
		Intent intent = new Intent();
		intent.setComponent(new ComponentName(packageName, componentName));
		intent.putExtra("key", new SerializableData());
		
		Toast.makeText(getApplicationContext(), "Send Serializable Intent " + intent, Toast.LENGTH_LONG).show();
		if(componentType.equals("activity")){
			startActivity(intent);
		}else if(componentType.equals("receiver")){
			sendBroadcast(intent);
		}else if(componentType.equals("service")){
			startService(intent); 
		}
	}

}
