using System.ComponentModel.DataAnnotations;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.EntityFrameworkCore;

namespace OnePieceCardManagement.Repository
{
    public interface IRepository<T> where T : class
    {
        IQueryable<T> Queryable();
        Task<T?> Get(int id, params Expression<Func<T, object>>[] includes);
        Task<List<T>> GetAll(params Expression<Func<T, object>>[] includes);
        Task<T> Insert(T entity);
        Task<IEnumerable<T>> InsertRange(IEnumerable<T> entity);
        Task<T> Update(T entity);
        Task<T> Delete(int id);
        Task<List<T>> Find(Expression<Func<T, bool>> filter, Func<IQueryable<T>, IOrderedQueryable<T>>? orderBy = null, params Expression<Func<T, object>>[] includes);
    }

    public class Repository<TModel, TDbContext> : IRepository<TModel> where TModel : class where TDbContext : DbContext, new()
    {
        protected readonly TDbContext _context;

        public Repository(TDbContext context)
        {
            _context = context;
        }

        public IQueryable<TModel> Queryable() => _context.Set<TModel>();

        public async Task<TModel?> Get(int id, params Expression<Func<TModel, object>>[] includes)
        {
            var lambdaId = BuildLambdaEqualPrimaryKey(id, typeof(TModel));

            var queryable = _context.Set<TModel>().Where((Expression<Func<TModel?, bool>>)lambdaId);

            queryable = includes.Aggregate(queryable, (current, include) => current.Include(include));

            return await queryable.FirstOrDefaultAsync();
        }

        public async Task<List<TModel>> GetAll(params Expression<Func<TModel, object>>[] includes)
        {
            var queryable = _context.Set<TModel>();

            IQueryable<TModel>? query = null;

            foreach (var include in includes) query = queryable.Include(include);

            return query != null ? await query.ToListAsync() : await queryable.ToListAsync();
        }

        public async Task<List<TModel>> Find(Expression<Func<TModel, bool>> filter, Func<IQueryable<TModel>, IOrderedQueryable<TModel>>? orderBy = null, params Expression<Func<TModel, object>>[] includes)
        {
            var queryable = _context.Set<TModel>().Where(filter);

            IQueryable<TModel>? query = null;

            foreach (var include in includes) query = queryable.Include(include);

            if (orderBy == null)
                return query != null ? await query.ToListAsync() : await queryable.ToListAsync();

            queryable = orderBy(query ?? queryable);

            return query != null ? await query.ToListAsync() : await queryable.ToListAsync();
        }

        public async Task<TModel> Insert(TModel entity)
        {
            _context.Set<TModel>().Add(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task<IEnumerable<TModel>> InsertRange(IEnumerable<TModel> entity)
        {
            _context.Set<TModel>().AddRange(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task<TModel> Update(TModel entity)
        {
            _context.Update(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task<TModel> Delete(int id)
        {
            var entity = await _context.Set<TModel>().FindAsync(id);
            if (entity == null) return entity;

            _context.Set<TModel>().Remove(entity);
            await _context.SaveChangesAsync();

            return entity;

        }

        private LambdaExpression BuildLambdaEqualPrimaryKey(object id, Type entityType)
        {
            var parameter = Expression.Parameter(entityType, entityType.Name);
            var property = Expression.Property(parameter, GetPrimaryKeysNames(entityType).Single());
            var equals = Expression.Equal(property, Expression.Constant(id));
            var lambdaType = typeof(Func<,>).MakeGenericType(entityType, typeof(bool));
            return Expression.Lambda(lambdaType, equals, parameter);
        }

        private IEnumerable<string> GetPrimaryKeysNames(Type entityType)
            => entityType.GetProperties().Where(p => p.GetCustomAttribute(typeof(KeyAttribute), false) != null).Select(p => p.Name);

    }
}