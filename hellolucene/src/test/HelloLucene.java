package test;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.RAMDirectory;
import org.apache.lucene.util.Version;

public class HelloLucene {
	/**
	 * 建立索引
	 */
	public void index(){
       IndexWriter writer = null;
       try {
    	 //1、创建director
//       Directory directory = new RAMDirectory();//索引建立在内存中
         Directory directory = FSDirectory.open(new File("e:/logaudit/index00"));
  		
         //2、创建IndexWriter
        IndexWriterConfig iwc = new IndexWriterConfig(Version.LUCENE_35,new StandardAnalyzer(Version.LUCENE_35));
		writer = new IndexWriter(directory,iwc);
		
		//3、创建document对象
		Document doc = null;
		
		//4、为document添加field
		File f = new File("e:/logaudit/txtexample");
		for(File file:f.listFiles()){
			doc = new Document();
			doc.add(new Field("content", new FileReader(file)));
			doc.add(new Field("name",file.getName(),Field.Store.YES,Field.Index.NOT_ANALYZED));
			doc.add(new Field("path",file.getAbsolutePath(),Field.Store.YES,Field.Index.NOT_ANALYZED));
			
		}	
		
		//5、通过indexWrite添加文档到索引中
		writer.addDocument(doc);
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}finally{
		if (writer!=null)
			try {
				writer.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
	}
}
