package com.oracle.choongangGroup.ry.service;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.ry.dao.AdminBookDao;
import com.oracle.choongangGroup.ry.model.BookCateVo;
import com.oracle.choongangGroup.ry.model.BookVo;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class AdminBookServiceImpl implements AdminBookService {
	
	private final AdminBookDao abd;

	@Override
	public List<BookCateVo> category() {
		List<BookCateVo> category = abd.category();
		return category;
	}

	@Override
	public void bookInsert(BookVo book) {
		abd.bookInsert(book);
		
	}

	@Override
	public List<BookVo> bookList() {
		List<BookVo> list = abd.bookList();
		return list;
	}

	@Override
	public BookVo bookDetailList(int bookId) {
		BookVo book = null; 
		book = abd.detailBookList(bookId);
		return book;
	}

	@Override
	public BookVo updateBook(int bookId) {
		BookVo books = null;
		books = abd.updateBookGet(bookId);
		return books;
		
	}

	@Override
	public void bookUpdate(BookVo book) {
		abd.updateBookPost(book);
		
	}

	@Override
	public void bookDelete(int bookId) {
		abd.deleteBook(bookId);
		
	}

	@Override
	public List<BookVo> bookSearchList(BookVo book) {
		List<BookVo> getSearch = abd.bookSearchList(book);
		return getSearch;
	}
	

}
