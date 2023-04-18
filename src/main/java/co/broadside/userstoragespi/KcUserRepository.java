package co.broadside.userstoragespi;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;

/**
 * Repository class for KCUser entity object
 * @author bhavyag
 */
public class KcUserRepository {

	static KcUserRepository kcUserRepository;

	private KcUserRepository() {
	}

	public static synchronized KcUserRepository getKcUserRepository() {
		if(kcUserRepository==null){
			kcUserRepository=new KcUserRepository();
		}
		return kcUserRepository;
	}

	List<KcUser> getAllUsers(EntityManager em) {
		TypedQuery<KcUser> query = em.createNamedQuery("getAllUsers", KcUser.class);

		List<KcUser> users = query.getResultList();
		/*
		 * List<UserModel> users = new LinkedList<>(); for (UserEntity entity : results)
		 * users.add(new KcUserAdapter(session, realm, model, entity));
		 */
		return users;
	}

	int getUsersCount(EntityManager em) {
		TypedQuery<KcUser> query = em.createNamedQuery("getUserCount", KcUser.class);
		return query.getFirstResult();
	}

	KcUser findUserById(EntityManager em, String id) {
		TypedQuery<KcUser> query = em.createNamedQuery("getUserByUserId", KcUser.class);
		query.setParameter("id", id);
		return query.getSingleResult();
	}

	public KcUser findUserByUsernameOrEmail(EntityManager em, String username) {
		TypedQuery<KcUser> query = em.createNamedQuery("getUserByUsername", KcUser.class);
		query.setParameter("username", username);
		return query.getResultStream().findFirst().orElse(null);
	}

	List<KcUser> findUsers(EntityManager em, String search) {
		TypedQuery<KcUser> query = em.createNamedQuery("searchForUser", KcUser.class);
		query.setParameter("search", "%" + search.toLowerCase() + "%");
		return query.getResultList();
	}

	boolean validateCredentials(EntityManager em, String username, String password) {
		return findUserByUsernameOrEmail(em, username).getPassword().equals(password);
	}

	boolean updateCredentials(EntityManager em, String username, String password) {
		KcUser d = findUserByUsernameOrEmail(em, username);
		d.setPassword(password);
		em.persist(d);
		return true;
	}

}