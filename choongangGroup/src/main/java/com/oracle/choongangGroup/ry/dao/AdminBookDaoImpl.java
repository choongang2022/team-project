package com.oracle.choongangGroup.ry.dao;

import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.oracle.choongangGroup.ry.model.BookCateVo;
import com.oracle.choongangGroup.ry.model.BookVo;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Repository
public class AdminBookDaoImpl implements AdminBookDao {
	
	private final SqlSession session;

	@Override
	public List<BookCateVo> category() {
		List<BookCateVo> category = new ArrayList<>();
		try {
			category = session.selectList("RYCategory");
			System.out.println("category.size" + category.size());
			
		} catch (Exception e) {
			System.out.println("e.getMessage()"+e.getMessage());
		}
		return category;
		
	}

	@Override
	public void bookInsert(BookVo book) {
		
		session.insert("BookInsert", book);
		
	}

	@Override
	public List<BookVo> bookList(BookVo book) {
		List<BookVo> list = session.selectList("BookList", book);
		return list;
	}

	@Override
	public BookVo detailBookList(int bookId) {
		BookVo book = new BookVo();
		book = session.selectOne("BookDetail", bookId);
		return book;
	}

	@Override
	public BookVo updateBookGet(int bookId) {
		BookVo books = new BookVo();
		books = session.selectOne("BookJoin", bookId);
		return books;
	}

	@Override
	public void updateBookPost(BookVo book) {
		
		session.update("BookUpdate", book);
		
	}

	@Override
	public void deleteBook(int bookId) {
		session.delete("BookDelete", bookId);
		
	}

	@Override
	public List<BookVo> bookSearchList(BookVo book) {
		List<BookVo> getBookList = null;
		try {
			getBookList= session.selectList("GetBookSearch", book);
			
		} catch (Exception e) {
			System.out.println("bookSearchList e.getMessage()"+e.getMessage());
		}
		return getBookList;
	}

	@Override
	public int processTotal() {
		int totProcessCnt = 0;
		try {
			totProcessCnt = session.selectOne("RYProcessTotal");
		} catch (Exception e) {
		}
		return totProcessCnt;
	}
}
